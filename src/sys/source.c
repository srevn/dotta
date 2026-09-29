/**
 * source.c - A source tree's ignore rules, found and read by dotta, matched by
 * base/gitignore in git's order.
 *
 * Implementation notes:
 *
 *   - Discovery is git's (setup.c setup_git_directory_gently_1), in libgit2's
 *     C: repository.c find_repo_traverse, is_valid_repository_path and
 *     read_gitfile. It is ported rather than asked of git_repository_discover
 *     for the one fact that call drops: the directory the `.git` was found in,
 *     which is the workdir unless the configuration says otherwise. A gitfile —
 *     a linked worktree's, a submodule's, a separate git dir's — names a gitdir
 *     that says nothing of where it was named from. Ported, the walk up is also
 *     one question per directory, memoised: a directory's answer is its own
 *     `.git`'s, or its parent's.
 *
 *   - One map holds every directory's answer under every spelling it was asked
 *     by. A spelling is resolved once (realpath, through the funnel), and the
 *     kernel's spelling is answered by the walk up — every prefix of a resolved
 *     path is resolved too, so the walk never resolves again, and a spelling
 *     with no link in it is its own kernel's spelling and one key. A spelled
 *     directory's entry is its kernel spelling's, shared.
 *
 *   - The repository is read as the invoker: raw stat, open and realpath for
 *     its layout, and libgit2 for its configuration (sys/source.h). The rule
 *     files are read through the funnel (sys/filesystem), without following a
 *     final link for an in-tree `.gitignore` (git's open_nofollow), O_NONBLOCK
 *     so a FIFO in one's place cannot wedge the open (git's own open would).
 *
 *   - Nothing is freed one by one: the answers, the rules and the errors live
 *     for the arena, and the one scratch — the rung asked — grows in it to the
 *     longest and is taken back by the next query. A failure is an answer like
 *     any other, minted once per cause (base/error.h "Lifetime").
 */

#include "sys/source.h"

#include <errno.h>
#include <fcntl.h>
#include <git2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/hashmap.h"
#include "base/string.h"
#include "sys/filesystem.h"
#include "sys/identity.h"

/* One file of a repository's stack, read once: its rules, or why they could not
 * be read. A file that is not there has no rules and no failure. */
typedef struct {
    const gitignore_ruleset_t *rules;  /* NULL: absent, as git reads it */
    const char *path;                  /* Where it is read from, absolute; NULL: no file */
    error_t failure;                   /* Why it could not be read; NULL when it was */
} file_t;

/* One repository, read once where discovery found it: where its rules are relative
 * to, how they compare, and its files. */
typedef struct {
    const char *workdir;               /* The kernel's spelling, through its '/'; NULL: none */
    gitignore_case_t casing;           /* core.ignoreCase */
    file_t exclude;                    /* $GIT_COMMON_DIR/info/exclude */
    file_t excludes;                   /* core.excludesFile, else git's default */
    hashmap_t *gitignores;             /* A directory beneath the workdir, through its '/' → file_t */
    error_t refusal;                   /* Why its configuration or layout could not be read */
} repository_t;

/* One directory's answer: the repository that governs it and where it stands
 * inside, or the failure that left it none. */
typedef struct {
    const char *place;                 /* The kernel's spelling, through its '/'; NULL with a failure */
    const repository_t *repository;    /* NULL: none governs it */
    const char *prefix;                /* Where it stands in the workdir, a suffix of `place`; NULL: nowhere */
    dev_t dev;                         /* Its filesystem, where the walk up stops */
    error_t failure;                   /* Why it has no answer; NULL when it has one */
} directory_t;

struct source_filter {
    arena_t *arena;                    /* Borrowed; backs all of it */
    hashmap_t *directories;            /* A directory through its '/', any spelling → directory_t */
    char *rung;                        /* Scratch: the rung asked, taken back by the next query */
    size_t rung_capacity;
};

/* ══════════════════════════════════════════════════════════════════
 * The layout, as the invoker
 * ══════════════════════════════════════════════════════════════════ */

/**
 * stat(2) of `name` in `directory` (spelled through its '/'), as the invoker:
 * 0, or -1 with errno — ENAMETOOLONG where the two make no path the kernel opens.
 */
static int source_stat(const char *directory, const char *name, struct stat *st) {
    char path[PATH_MAX];
    if ((size_t) snprintf(path, sizeof(path), "%s%s", directory, name) >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return stat(path, st);
}

/**
 * A path a file of the layout names — a `.git` file's gitdir, a `commondir` —
 * read as the invoker, as git reads one: the file's text with its trailing CR
 * and LF off (setup.c read_gitfile_gently, get_common_dir_noenv), into the arena.
 */
static error_t source_line(
    source_filter_t *f, const char *directory, const char *name, const char **out
) {
    char path[PATH_MAX];
    if ((size_t) snprintf(path, sizeof(path), "%s%s", directory, name) >= sizeof(path)) {
        return error_from_errno(ENAMETOOLONG, "Failed to open '%s%s'", directory, name);
    }

    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return error_from_errno(errno, "Failed to open '%s'", path);
    }

    buffer_t text = BUFFER_INIT;
    error_t err = fs_read_fd(fd, &text);
    close(fd);
    if (err) {
        return error_wrap(err, "Failed to read '%s'", path);
    }

    size_t len = text.size;
    while (len > 0 && (text.data[len - 1] == '\n' || text.data[len - 1] == '\r')) len--;

    *out = arena_strndup(f->arena, text.data, len);
    buffer_deinit(&text);

    return NULL;
}

/**
 * The directory the kernel spells `path` as, through its '/', into the arena —
 * or NULL where it names none it can resolve (errno says why).
 */
static const char *source_resolve(source_filter_t *f, const char *path) {
    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) return NULL;

    size_t len = strlen(resolved);
    return arena_str_format(f->arena, "%s%s", resolved, resolved[len - 1] == '/' ? "" : "/");
}

/**
 * The common dir of `gitdir` (through its '/'), or NULL where `gitdir` is no
 * git directory
 *
 * libgit2's is_valid_repository_path: a HEAD file, and objects/ and refs/
 * directories in the common dir — the one a `commondir` file names, a linked
 * worktree's, else the gitdir itself. A reftable or sha256 repository keeps all
 * three, which is what lets the rules be read where libgit2 cannot open one. A
 * `commondir` naming nothing names no git directory.
 */
static error_t source_commondir(source_filter_t *f, const char *gitdir, const char **out) {
    *out = NULL;

    struct stat st;
    if (source_stat(gitdir, "HEAD", &st) != 0 || !S_ISREG(st.st_mode)) return NULL;

    const char *commondir = gitdir;
    if (source_stat(gitdir, "commondir", &st) == 0) {
        const char *named = NULL;
        RETURN_IF_ERROR(source_line(f, gitdir, "commondir", &named));

        commondir = source_resolve(
            f, named[0] == '/' ? named : arena_str_format(f->arena, "%s%s", gitdir, named)
        );
        if (!commondir) return NULL;
    }

    if (source_stat(commondir, "objects", &st) != 0 || !S_ISDIR(st.st_mode)) return NULL;
    if (source_stat(commondir, "refs", &st) != 0 || !S_ISDIR(st.st_mode)) return NULL;

    *out = commondir;
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * The rule files, through the funnel
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Read one file of the stack into `out`, compiled as the repository compares
 * letters
 *
 * `nofollow` is O_NOFOLLOW for an in-tree `.gitignore`, which git opens without
 * following a final link, and 0 for the two files git follows. What git reads
 * as absent by rule is absent here: a file that is not there, and a link where
 * none is followed. Anything else is the file's failure (sys/source.h).
 */
static void source_read(
    source_filter_t *f, const char *path, int nofollow, gitignore_case_t casing,
    file_t *out
) {
    *out = (file_t){ .path = path };

    int fd = fs_open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | nofollow, 0);
    if (fd < 0) {
        /* Absent: nothing there, or nothing a directory in the way can hold. A
         * final link refuses a no-follow open with an errno each kernel spells
         * its own way, so a look says whether it is one — as the capture does
         * (infra/content.c). */
        int open_errno = errno;
        struct stat st;
        if (open_errno == ENOENT || open_errno == ENOTDIR) return;
        if (nofollow && fs_lstat(path, &st) == 0 && S_ISLNK(st.st_mode)) return;

        out->failure = error_from_errno(open_errno, "Failed to open '%s'", path);
        return;
    }

    /* The whole file, a regular one: a directory or a FIFO in its place is refused
     * here (fs_read_fd), not read as nothing. */
    buffer_t text = BUFFER_INIT;
    error_t err = fs_read_fd(fd, &text);
    close(fd);
    if (err) {
        out->failure = error_wrap(err, "Failed to read '%s'", path);
        return;
    }

    /* Text, as a .dottaignore must be (core/ignore.h ignore_blob_text): a NUL
     * would end the ruleset's reading of the file, and whatever stood behind it
     * would be lost without a word. */
    if (memchr(text.data, '\0', text.size)) {
        buffer_deinit(&text);
        out->failure = ERROR(ERR_VALIDATION, "'%s' is not text: it holds a NUL byte", path);
        return;
    }

    gitignore_ruleset_t *rules = gitignore_ruleset_create(f->arena, casing);
    err = gitignore_ruleset_append_file(rules, text.data, 0);
    buffer_deinit(&text);
    if (err) {
        out->failure = error_wrap(err, "Failed to parse '%s'", path);
        return;
    }

    out->rules = rules;
}

/**
 * The `.gitignore` of one directory beneath the workdir — the first `level` bytes
 * of `rung`, through its '/', "" at the workdir — read once, never through a
 * final link (git's open_nofollow).
 */
static const file_t *source_gitignore(
    source_filter_t *f, const repository_t *repository, const char *rung, size_t level
) {
    file_t *file = hashmap_get_n(repository->gitignores, rung, level);
    if (file) return file;

    file = arena_alloc(f->arena, sizeof(*file));
    source_read(
        f, arena_str_format(f->arena, "%s%.*s.gitignore", repository->workdir, (int) level, rung),
        O_NOFOLLOW, repository->casing, file
    );

    hashmap_set(repository->gitignores, arena_strndup(f->arena, rung, level), file);
    return file;
}

/* ══════════════════════════════════════════════════════════════════
 * The repository
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Add one file to the configuration at `level`. A file the invoker cannot read
 * is absent, as to git: libgit2 answers GIT_ENOTFOUND for one (config_file_open),
 * and its own repository open reads that as absent too (repository.c load_config).
 *
 * @return 0, or libgit2's error for a file that does not parse
 */
static int source_config(git_config *config, const char *path, git_config_level_t level) {
    int rc = git_config_add_file_ondisk(config, path, level, NULL, 0);

    return rc == GIT_ENOTFOUND ? 0 : rc;
}

/**
 * A boolean of the configuration; false where it is not set.
 *
 * @return 0, or libgit2's error for a value that does not parse
 */
static int source_bool(git_config *config, const char *key, bool *out) {
    int value = 0;
    int rc = git_config_get_bool(&value, config, key);

    *out = rc == 0 && value;
    return rc == GIT_ENOTFOUND ? 0 : rc;
}

/**
 * A string of the configuration, into the arena; NULL where it is not set.
 *
 * @return 0, or libgit2's error
 */
static int source_string(
    source_filter_t *f, git_config *config, const char *key, const char **out
) {
    git_buf value = GIT_BUF_INIT;
    int rc = git_config_get_string_buf(&value, config, key);

    *out = rc == 0 ? arena_strdup(f->arena, value.ptr) : NULL;
    git_buf_dispose(&value);
    return rc == GIT_ENOTFOUND ? 0 : rc;
}

/**
 * The repository discovery found: `gitdir` and its `commondir` (source_commondir),
 * reached through the `.git` of `found`, or at `gitdir` itself where `found` is
 * NULL (a bare repository, or a walk begun inside a gitdir)
 *
 * Its configuration is composed as libgit2's repository open composes one
 * (repository.c load_config), less the repository a conditional include needs:
 * the repository's own file, its worktree's where that file sets
 * extensions.worktreeConfig, then the global, XDG, system and programdata files
 * libgit2 finds — read and let go. Its workdir is git's (setup.c
 * setup_discovered_git_dir): a linked worktree's is where its `.git` was found
 * — it reads neither key below from the common config
 * (check_repository_format_gently) — and any other's is core.worktree, relative
 * to the gitdir, or where the `.git` was found unless core.bare, or none. A
 * repository with no workdir answers for nothing, and reads no file.
 *
 * Never NULL: what could not be read is the repository's refusal, answered for
 * every directory it governs.
 */
static const repository_t *source_repository(
    source_filter_t *f, const char *found, const char *gitdir, const char *commondir
) {
    repository_t *r = arena_calloc(f->arena, 1, sizeof(*r));
    r->gitignores = hashmap_borrow(f->arena, 0);

    bool linked = strcmp(commondir, gitdir) != 0;
    bool worktree_config = false, bare = false, ignorecase = false;
    const char *worktree = NULL, *excludesfile = NULL;

    /* One configuration, read whole and let go before anything is answered. An
     * extension is the repository's own, so its file is asked alone whether a
     * worktree's is read (git's check_repository_format reads nothing else); a
     * file that does not parse is libgit2's error, naming the file. */
    static const struct {
        int (*find)(git_buf *path);
        git_config_level_t level;
    } levels[] = {
        { git_config_find_global,      GIT_CONFIG_LEVEL_GLOBAL      },
        { git_config_find_xdg,         GIT_CONFIG_LEVEL_XDG         },
        { git_config_find_system,      GIT_CONFIG_LEVEL_SYSTEM      },
        { git_config_find_programdata, GIT_CONFIG_LEVEL_PROGRAMDATA },
    };

    git_config *config = NULL;
    int rc = git_config_new(&config);
    if (rc == 0) {
        rc = source_config(
            config, arena_str_format(f->arena, "%sconfig", commondir), GIT_CONFIG_LEVEL_LOCAL
        );
    }
    if (rc == 0) rc = source_bool(config, "extensions.worktreeconfig", &worktree_config);
    if (rc == 0 && worktree_config) {
        rc = source_config(
            config, arena_str_format(f->arena, "%sconfig.worktree", gitdir),
            GIT_CONFIG_LEVEL_WORKTREE
        );
    }
    for (size_t i = 0; rc == 0 && i < sizeof(levels) / sizeof(levels[0]); i++) {
        git_buf path = GIT_BUF_INIT;
        if (levels[i].find(&path) == 0) rc = source_config(config, path.ptr, levels[i].level);
        git_buf_dispose(&path);
    }
    if (rc == 0) rc = source_bool(config, "core.bare", &bare);
    if (rc == 0) rc = source_bool(config, "core.ignorecase", &ignorecase);
    if (rc == 0) rc = source_string(f, config, "core.worktree", &worktree);
    if (rc == 0) rc = source_string(f, config, "core.excludesfile", &excludesfile);
    git_config_free(config);

    if (rc < 0) {
        r->refusal = error_from_git(rc);
        return r;
    }

    /* The workdir, in git's order. A core.worktree that names nothing is git's
     * refusal too ("Invalid path"). */
    if (found && linked) {
        r->workdir = found;
    } else if (!linked && worktree) {
        r->workdir = source_resolve(
            f, worktree[0] == '/' ? worktree : arena_str_format(f->arena, "%s%s", gitdir, worktree)
        );
        if (!r->workdir) {
            r->refusal = error_from_errno(
                errno, "Failed to resolve core.worktree '%s' of '%s'", worktree, gitdir
            );
            return r;
        }
    } else if (found && !bare) {
        r->workdir = found;
    }
    if (!r->workdir) return r;

    r->casing = ignorecase ? GITIGNORE_CASE_INSENSITIVE : GITIGNORE_CASE_SENSITIVE;

    /* The two files every rung falls back to, read now: info/exclude in the common
     * dir, which a linked worktree shares; and core.excludesFile — relative to
     * the workdir, where git reads it from; none where it is set empty — or,
     * unset, git's default (dir.c xdg_config_home). */
    source_read(
        f, arena_str_format(f->arena, "%sinfo/exclude", commondir), 0, r->casing,
        &r->exclude
    );

    if (!excludesfile) {
        const char *xdg = getenv("XDG_CONFIG_HOME");
        source_read(
            f, xdg && *xdg ? str_path_join(f->arena, xdg, "git/ignore")
                           : str_path_join(f->arena, identity()->home, ".config/git/ignore"),
            0, r->casing, &r->excludes
        );
    } else if (*excludesfile) {
        const char *path = NULL;
        error_t err = fs_expand_tilde(excludesfile, f->arena, &path);
        if (err) {
            r->excludes.failure = error_wrap(err, "Failed to read core.excludesFile");
        } else {
            source_read(
                f, path[0] == '/' ? path : str_path_join(f->arena, r->workdir, path), 0,
                r->casing, &r->excludes
            );
        }
    }

    return r;
}

/* ══════════════════════════════════════════════════════════════════
 * Discovery
 * ══════════════════════════════════════════════════════════════════ */

/**
 * How much of `spelling` names the directory above the one its first `len` bytes
 * name, through its '/' — a directory's parent, or a rung's next `.gitignore`
 * up; 0 where none is above a relative one
 */
static size_t source_parent(const char *spelling, size_t len) {
    size_t at = len - 1;                /* the '/' that ends the directory */
    while (at > 0 && spelling[at - 1] != '/') at--;

    return at;
}

/**
 * The repository found at `directory` (the kernel's spelling, through its '/')
 * — one level of git's walk up: the `.git` it holds, a directory or a file naming
 * one; failing that, the directory itself as a git directory. NULL where neither
 * is one.
 *
 * An invalid `.git` directory is walked past, as git walks past one. A `.git`
 * file is not: one that is no gitfile, or names no git directory, is this
 * directory's failure — git refuses to work beneath it (setup.c
 * read_gitfile_gently).
 */
static error_t source_found(source_filter_t *f, const char *directory, const repository_t **out) {
    *out = NULL;

    struct stat st;
    const char *commondir = NULL;

    if (source_stat(directory, ".git", &st) == 0) {
        /* A `.git` directory: the repository, where it is one. */
        if (S_ISDIR(st.st_mode)) {
            const char *gitdir = arena_str_format(f->arena, "%s.git/", directory);
            RETURN_IF_ERROR(source_commondir(f, gitdir, &commondir));
            if (commondir) {
                *out = source_repository(f, directory, gitdir, commondir);
                return NULL;
            }
        } else if (S_ISREG(st.st_mode)) {
            /* A `.git` file: the gitdir it names, relative to its own directory
             * — a linked worktree's, a submodule's, a separate git dir's. */
            const char *named = NULL;
            RETURN_IF_ERROR(source_line(f, directory, ".git", &named));
            if (strncmp(named, "gitdir: ", 8) != 0) {
                return ERROR(ERR_VALIDATION, "Invalid gitfile format: '%s.git'", directory);
            }

            named += 8;
            const char *gitdir = source_resolve(
                f, named[0] == '/' ? named : arena_str_format(f->arena, "%s%s", directory, named)
            );
            if (gitdir) RETURN_IF_ERROR(source_commondir(f, gitdir, &commondir));
            if (!commondir) {
                return ERROR(
                    ERR_VALIDATION, "'%s.git' names no git repository: '%s'", directory, named
                );
            }

            *out = source_repository(f, directory, gitdir, commondir);
            return NULL;
        }
    }

    /* The directory itself: a bare repository, or a walk begun inside a gitdir.
     * No `.git` was found in it, so no workdir either unless core.worktree names
     * one. */
    RETURN_IF_ERROR(source_commondir(f, directory, &commondir));
    if (commondir) *out = source_repository(f, NULL, directory, commondir);

    return NULL;
}

/**
 * The answer for a directory in the kernel's spelling, through its '/' — the
 * repository at it, else its parent's answer, unless its parent stands on another
 * filesystem, where the walk up stops (libgit2's across_fs 0, git's default)
 *
 * A directory the invoker cannot look at is one discovery cannot examine: it
 * reads as its parent reads (libgit2 walks past a level it cannot stat). Memoised
 * in the one map every spelling shares; the prefix points into the key.
 */
static const directory_t *source_place(source_filter_t *f, const char *physical, size_t len) {
    directory_t *d = hashmap_get_n(f->directories, physical, len);
    if (d) return d;

    char *key = arena_strndup(f->arena, physical, len);
    d = arena_calloc(f->arena, 1, sizeof(*d));
    d->place = key;

    struct stat st;
    const repository_t *repository = NULL;

    int rc = stat(key, &st);
    if (rc == 0) {
        d->dev = st.st_dev;
        d->failure = source_found(f, key, &repository);
    }

    /* None at this level: the parent's answer, where the walk up may reach it. */
    if (!d->failure && !repository && len > 1) {
        const directory_t *parent = source_place(f, key, source_parent(key, len));
        if (rc != 0) d->dev = parent->dev;
        if (d->dev == parent->dev) {
            repository = parent->repository;
            d->failure = parent->failure;
        }
    }

    /* Where the directory stands inside the repository's workdir: a suffix of
     * the key, "" at the workdir, nowhere outside it or where there is none. */
    if (repository && !d->failure) {
        d->repository = repository;
        d->failure = repository->refusal;

        size_t root = repository->workdir ? strlen(repository->workdir) : 0;
        if (!d->failure && root && strncmp(key, repository->workdir, root) == 0) {
            d->prefix = key + root;
        }
    }

    hashmap_set(f->directories, key, d);
    return d;
}

/**
 * The answer for the directory `path`'s first `len` bytes spell, through its
 * '/' — its kernel spelling's (source_place), resolved once per spelling
 *
 * A directory that is not there — `ignore --test` asks about a path before it
 * is made — is spelled as it will be once it is, beneath its parent's kernel
 * spelling, and reads as its parent reads until then: git's rules are the path's,
 * whether it stands or not. A spelling that resolves to nothing else is its own
 * failure.
 */
static const directory_t *source_directory(source_filter_t *f, const char *path, size_t len) {
    directory_t *d = hashmap_get_n(f->directories, path, len);
    if (d) return d;

    /* The kernel's spelling, through the funnel: a directory a sudo'd walk entered
     * is one it resolves. PATH_MAX for realpath, one more for the '/'. */
    char spelled[PATH_MAX], physical[PATH_MAX + 1];
    size_t n = (size_t) snprintf(spelled, sizeof(spelled), "%.*s", (int) len, path);

    if (n >= sizeof(spelled)) {
        d = arena_calloc(f->arena, 1, sizeof(*d));
        d->failure = error_from_errno(
            ENAMETOOLONG, "Failed to resolve path '%.*s'", (int) len, path
        );
    } else if (fs_realpath(spelled, physical)) {
        n = strlen(physical);
        if (physical[n - 1] != '/') {
            physical[n++] = '/';
            physical[n] = '\0';
        }
        d = (directory_t *) source_place(f, physical, n);

        /* A spelling that is its own kernel's is the entry the walk up just made:
         * one key, never two. */
        if (n == len && memcmp(physical, spelled, n) == 0) return d;
    } else if ((errno == ENOENT || errno == ENOTDIR) && len > 1) {
        /* Its parent's answer stands for it where the parent has none — a failure
         * — and otherwise its own spelling beneath the parent's place does. */
        size_t above = source_parent(spelled, len);
        d = (directory_t *) source_directory(f, path, above);
        if (d->place) {
            n = (size_t) snprintf(physical, sizeof(physical), "%s%s", d->place, spelled + above);
            if (n < sizeof(physical)) {
                d = (directory_t *) source_place(f, physical, n);
            } else {
                d = arena_calloc(f->arena, 1, sizeof(*d));
                d->failure = error_from_errno(ENAMETOOLONG, "Failed to resolve path '%s'", spelled);
            }
        }
    } else {
        d = arena_calloc(f->arena, 1, sizeof(*d));
        d->failure = error_from_errno(errno, "Failed to resolve path '%s'", spelled);
    }

    hashmap_set(f->directories, arena_strndup(f->arena, path, len), d);
    return d;
}

/* ══════════════════════════════════════════════════════════════════
 * The rung
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The rule of `repository`'s stack that decides `rung` — git's
 * last_matching_pattern_from_lists, the rung spelled from the workdir: the first
 * list with a rule that matches decides, and a file that could not be read answers
 * its failure where it comes in that order.
 */
static error_t source_decide(
    source_filter_t *f, const repository_t *repository, const char *rung, bool is_dir,
    source_rule_t *out
) {
    *out = (source_rule_t){ 0 };

    /* Each .gitignore from the rung's own directory up to the workdir, deepest
     * first, reading the rung from its own directory: a suffix of it. A list
     * that decides here is never read past, so no file above it can fail the
     * rung. */
    const char *slash = strrchr(rung, '/');
    for (size_t level = slash ? (size_t) (slash - rung) + 1 : 0;;) {
        const file_t *file = source_gitignore(f, repository, rung, level);
        if (file->failure) return file->failure;

        const gitignore_rule_t *rule = gitignore_ruleset_find(file->rules, rung + level, is_dir);
        if (rule) {
            *out = (source_rule_t){ rule, file->path };
            return NULL;
        }
        if (level == 0) break;
        level = source_parent(rung, level);
    }

    /* Then info/exclude and the excludes file, reading the whole rung: git pushes
     * the two the other way round and reads its lists last first (dir.c
     * setup_standard_excludes). */
    const file_t *files[] = { &repository->exclude, &repository->excludes };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if (files[i]->failure) return files[i]->failure;

        const gitignore_rule_t *rule = gitignore_ruleset_find(files[i]->rules, rung, is_dir);
        if (rule) {
            *out = (source_rule_t){ rule, files[i]->path };
            return NULL;
        }
    }

    return NULL;
}

/**
 * The rung `name` is in its directory's workdir: the directory's prefix and the
 * name, spelled in the filter's scratch, which the next query takes back
 */
static char *source_rung(source_filter_t *f, const char *prefix, const char *name) {
    size_t head = strlen(prefix), tail = strlen(name);

    f->rung = arena_grow(f->arena, f->rung, &f->rung_capacity, head + tail + 1, 1);
    memcpy(f->rung, prefix, head);
    memcpy(f->rung + head, name, tail + 1);

    return f->rung;
}

/* ══════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════ */

source_filter_t *source_filter_create(arena_t *arena) {
    CHECK_NULL(arena);

    source_filter_t *f = arena_calloc(arena, 1, sizeof(*f));
    f->arena = arena;
    f->directories = hashmap_borrow(arena, 0);

    return f;
}

error_t source_filter_find(
    source_filter_t *f, const char *path, bool is_dir, source_rule_t *out
) {
    CHECK_NULL(f);
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_ARG(path[0] == '/', "source_filter requires absolute paths");

    *out = (source_rule_t){ 0 };

    /* The name the path ends in, and the directory it stands in — through the
     * separator, so "/" is a directory like any other and the name is never empty
     * and never holds one. A path that names no entry asks nothing. */
    const char *name = strrchr(path, '/') + 1;
    if (!*name) return NULL;

    const directory_t *d = source_directory(f, path, (size_t) (name - path));
    if (d->failure) return d->failure;
    if (!d->prefix) return NULL;

    return source_decide(f, d->repository, source_rung(f, d->prefix, name), is_dir, out);
}

error_t source_filter_excludes(
    source_filter_t *f, const char *abs_path, bool is_dir, bool *out
) {
    CHECK_NULL(f);
    CHECK_NULL(abs_path);
    CHECK_NULL(out);
    CHECK_ARG(abs_path[0] == '/', "source_filter requires absolute paths");

    *out = false;

    const char *name = strrchr(abs_path, '/') + 1;
    if (!*name) return NULL;

    const directory_t *d = source_directory(f, abs_path, (size_t) (name - abs_path));
    if (d->failure) return d->failure;
    if (!d->prefix) return NULL;

    /* git's climb (dir.c prep_exclude), over the rungs the kernel spells: every
     * directory from the workdir down, shallowest first and each as a directory,
     * then the entry. Each rung is cut in the scratch in place, and the scratch
     * is the query's, so nothing is put back on the way out. */
    char *rung = source_rung(f, d->prefix, name);
    source_rule_t decided;

    for (char *slash = strchr(rung, '/'); slash; slash = strchr(slash + 1, '/')) {
        *slash = '\0';
        RETURN_IF_ERROR(source_decide(f, d->repository, rung, true, &decided));
        if (decided.rule && !gitignore_rule_negated(decided.rule)) {
            *out = true;
            return NULL;
        }
        *slash = '/';
    }

    RETURN_IF_ERROR(source_decide(f, d->repository, rung, is_dir, &decided));
    *out = decided.rule && !gitignore_rule_negated(decided.rule);

    return NULL;
}
