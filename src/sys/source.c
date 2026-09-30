/**
 * source.c - A source tree's ignore rules, found and read by dotta, matched by
 * base/gitignore in git's order.
 *
 * Implementation notes:
 *
 *   - Discovery is git's (setup.c repo_discovery_find_dir), in libgit2's C:
 *     repository.c find_repo_traverse, is_valid_repository_path and read_gitfile.
 *     It is ported rather than asked of git_repository_discover for the one fact
 *     that call drops: the directory the `.git` was found in, which is the workdir
 *     unless the format says otherwise. A gitfile — a linked worktree's, a
 *     submodule's, a separate git dir's — names a gitdir that says nothing of
 *     where it was named from. Ported, the walk up is also one question per
 *     directory, memoised: a directory's answer is its own `.git`'s, or its
 *     parent's.
 *
 *   - One map holds every directory's answer under every spelling it was asked
 *     by. A spelling is resolved once (realpath, through the funnel), and the
 *     kernel's spelling is answered by the walk up — every prefix of a resolved
 *     path is resolved too, so the walk never resolves again, and a spelling
 *     with no link in it is its own kernel's spelling and one key. A spelled
 *     directory's entry is its kernel spelling's, shared, and keeps that spelling:
 *     what a climb over a place climbs (source_filter_physical).
 *
 *   - The repository is read as the invoker: raw stat, open and realpath for
 *     its layout, and libgit2 for its configuration (sys/source.h). The rule
 *     files are read through the funnel (sys/filesystem), without following a
 *     final link for an in-tree `.gitignore` (git's open_nofollow), O_NONBLOCK
 *     so a FIFO in one's place cannot wedge the open (git's own open would).
 *
 *   - A repository's lists are one chain, in the order git reads them: each
 *     `.gitignore` from a directory up to the workdir, then info/exclude, then
 *     the excludes file. It is git's exclude stack (dir.c prep_exclude), kept
 *     per directory rather than per traversal — what a memo of point queries
 *     can keep — so a rung is asked of its directory's list and every list after
 *     it, and nothing is looked up twice.
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

/* One list of a repository's stack, read once: a file's rules, or why they could
 * not be read, and the list git reads after it where these are silent. A file
 * that is not there has no rules and no failure. A `.gitignore` is a list of
 * the repository that reads it, not of the directory it stands in: a core.worktree
 * above its `.git` makes directories another repository governs this one's too,
 * and each repository compiles the file with its own core.ignoreCase. */
typedef struct file file_t;
struct file {
    const gitignore_ruleset_t *rules;  /* NULL: absent, as git reads it */
    const char *path;                  /* Where it is read from, absolute; NULL: no file */
    error_t failure;                   /* Why it could not be read; NULL when it was */
    size_t root;                       /* Its directory beneath the workdir, through its '/': a rung's bytes it reads past */
    const file_t *next;                /* The list git reads after it; NULL: the last */
};

/* One repository, read once where discovery found it: where its rules are relative
 * to, how they compare, and its lists. */
typedef struct {
    const char *workdir;               /* The kernel's spelling, through its '/'; NULL: none */
    gitignore_case_t casing;           /* core.ignoreCase */
    hashmap_t *gitignores;             /* A directory beneath the workdir, through its '/' → its .gitignore */
    file_t info_exclude;               /* $GIT_COMMON_DIR/info/exclude, after every .gitignore */
    file_t excludes_file;              /* core.excludesFile, else git's default: the last list */
    error_t failure;                   /* Why its configuration or layout could not be read */
} repository_t;

/* One directory's answer: its kernel spelling, the repository that governs it
 * and where it stands inside, or the failure that left it none. */
typedef struct {
    const char *physical;              /* The kernel's spelling, through its '/': its key; NULL: it resolves to nothing */
    const repository_t *repository;    /* NULL: none governs it */
    const char *prefix;                /* Where it stands in the workdir, a suffix of `physical`; NULL: nowhere */
    dev_t dev;                         /* Its filesystem, where the walk up stops */
    error_t failure;                   /* Why it has no answer; NULL when it has one */
} directory_t;

struct source_filter {
    arena_t *arena;                    /* Borrowed; backs all of it */
    hashmap_t *directories;            /* A directory through its '/', any spelling → directory_t */
    hashmap_t *ceilings;               /* GIT_CEILING_DIRECTORIES, each through its '/'; NULL: none */
    bool across;                       /* GIT_DISCOVERY_ACROSS_FILESYSTEM: the walk up crosses them */
    error_t failure;                   /* Why the environment gives discovery no reading */
    char *rung;                        /* Scratch: the rung asked, taken back by the next query */
    size_t rung_capacity;
};

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
 * directories in the common dir. git reads HEAD's content besides (setup.c
 * validate_headref) and takes a HEAD that is a link into refs/, so a directory
 * holding a HEAD git cannot read as a ref is one git walks past and this reads.
 * The common dir is the one a `commondir` file names, a linked worktree's, else
 * the gitdir itself: `gitdir`, the very pointer, so a caller tells a gitdir with
 * a common dir of its own by the file (git's has_common), whatever the file names.
 * A reftable or sha256 repository keeps all three, which is what lets the rules
 * be read where libgit2 cannot open one. A `commondir` that names nothing is a
 * failure, as git dies resolving one (setup.c get_common_dir_noenv).
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
        if (!commondir) {
            return error_from_errno(
                errno, "Failed to resolve commondir '%s' of '%s'", named, gitdir
            );
        }
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
 * none is followed. Anything else is the file's failure (sys/source.h). `out`
 * is made whole, its place in the chain left to the caller.
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
 * The `.gitignore` of one directory beneath the workdir — the first `root` bytes
 * of `rung`, through its '/', "" at the workdir — read once, never through a
 * final link (git's open_nofollow), and chained to the list git reads after it:
 * the directory above's, or at the workdir, info/exclude.
 */
static const file_t *source_gitignore(
    source_filter_t *f, const repository_t *repository, const char *rung, size_t root
) {
    file_t *file = hashmap_get_n(repository->gitignores, rung, root);
    if (file) return file;

    file = arena_alloc(f->arena, sizeof(*file));
    source_read(
        f, arena_str_format(f->arena, "%s%.*s.gitignore", repository->workdir, (int) root, rung),
        O_NOFOLLOW, repository->casing, file
    );
    file->root = root;
    file->next = root
        ? source_gitignore(f, repository, rung, source_parent(rung, root))
        : &repository->info_exclude;

    hashmap_set(repository->gitignores, arena_strndup(f->arena, rung, root), file);
    return file;
}

/* ══════════════════════════════════════════════════════════════════
 * The repository
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Add one file to the configuration at `level`. A file that is not there is absent.
 * One there that the invoker cannot read — libgit2 answers GIT_ENOTFOUND for it
 * (config_file_open) — is the repository's failure where it is its own, as git
 * refuses the repository (config.c do_git_config_sequence, access_or_die), and
 * absent where it is the machine's, as git skips a global or XDG file it cannot
 * read. git refuses its system file too, but the one libgit2 finds is libgit2's
 * (/etc), which need not be git's, so it is read as the machine's.
 *
 * @return NULL, or why the file could not be read: one that does not parse, or
 *         one of the repository's own that the invoker cannot read
 */
static error_t source_config(git_config *config, const char *path, git_config_level_t level) {
    int rc = git_config_add_file_ondisk(config, path, level, NULL, 0);
    if (rc != GIT_ENOTFOUND) return rc < 0 ? error_from_git(rc) : NULL;

    return level >= GIT_CONFIG_LEVEL_LOCAL
        ? error_from_errno(EACCES, "Failed to read '%s'", path) : NULL;
}

/**
 * A boolean of the configuration; false where it is not set.
 *
 * @return NULL, or libgit2's error for a value that does not parse
 */
static error_t source_bool(git_config *config, const char *key, bool *out) {
    int value = 0;
    int rc = git_config_get_bool(&value, config, key);

    *out = rc == 0 && value;
    return rc < 0 && rc != GIT_ENOTFOUND ? error_from_git(rc) : NULL;
}

/**
 * A string of the configuration, into the arena; NULL where it is not set.
 *
 * @return NULL, or libgit2's error
 */
static error_t source_string(
    source_filter_t *f, git_config *config, const char *key, const char **out
) {
    git_buf value = GIT_BUF_INIT;
    int rc = git_config_get_string_buf(&value, config, key);

    *out = rc == 0 ? arena_strdup(f->arena, value.ptr) : NULL;
    git_buf_dispose(&value);
    return rc < 0 && rc != GIT_ENOTFOUND ? error_from_git(rc) : NULL;
}

/**
 * The repository discovery found: `gitdir` and its `commondir` (source_commondir),
 * reached through the `.git` of `found`, or at `gitdir` itself where `found` is
 * NULL (a bare repository, or a walk begun inside a gitdir)
 *
 * git reads a repository twice, and so does this. Its format first, from its
 * own files alone (setup.c read_and_verify_repository_format): the config, which
 * declares a format (core.repositoryformatversion) or has none, and the worktree's
 * own config.worktree where the format extends to it (extensions.worktreeConfig)
 * — core.bare and core.worktree are read there and nowhere else. Then its
 * configuration, composed as libgit2's repository open composes one (repository.c
 * load_config), less the repository a conditional include needs: the global,
 * XDG, system and programdata files libgit2 finds, below the repository's own.
 * Its workdir is git's (setup.c repo_discover_implicit_gitdir): core.worktree,
 * relative to the gitdir, else where the `.git` was found unless core.bare, else
 * none. A repository with no workdir answers for nothing, and reads no file.
 *
 * Never NULL: what could not be read is the repository's failure, answered for
 * every directory it governs.
 */
static const repository_t *source_repository(
    source_filter_t *f, const char *found, const char *gitdir, const char *commondir
) {
    repository_t *r = arena_calloc(f->arena, 1, sizeof(*r));
    r->gitignores = hashmap_borrow(f->arena, 0);

    const char *version = NULL, *worktree = NULL, *excludesfile = NULL;
    bool worktree_config = false, bare = false, ignorecase = false;

    static const struct {
        int (*find)(git_buf *path);
        git_config_level_t level;
    } levels[] = {
        { git_config_find_global,      GIT_CONFIG_LEVEL_GLOBAL      },
        { git_config_find_xdg,         GIT_CONFIG_LEVEL_XDG         },
        { git_config_find_system,      GIT_CONFIG_LEVEL_SYSTEM      },
        { git_config_find_programdata, GIT_CONFIG_LEVEL_PROGRAMDATA },
    };

    /* One composition serves both readings, read and let go before anything is
     * answered: a file that does not parse is libgit2's error, naming the file,
     * and one of the repository's own that the invoker cannot read is its failure
     * (source_config). */
    git_config *config = NULL;
    int rc = git_config_new(&config);
    if (rc < 0) {
        r->failure = error_from_git(rc);
        return r;
    }

    /* The format, from the repository's own files before anything joins them:
     * the config alone says whether the worktree's is read. Every key is read
     * whether it counts or not, as git parses the file whole (setup.c
     * check_repo_format): a value that does not parse is its refusal either way. */
    error_t err = source_config(
        config, arena_str_format(f->arena, "%sconfig", commondir), GIT_CONFIG_LEVEL_LOCAL
    );
    if (!err) err = source_string(f, config, "core.repositoryformatversion", &version);
    if (!err) err = source_bool(config, "extensions.worktreeconfig", &worktree_config);
    if (!err && version && worktree_config) {
        err = source_config(
            config, arena_str_format(f->arena, "%sconfig.worktree", gitdir),
            GIT_CONFIG_LEVEL_WORKTREE
        );
    }
    if (!err) err = source_bool(config, "core.bare", &bare);
    if (!err) err = source_string(f, config, "core.worktree", &worktree);

    /* Then the configuration: every level, the machine's files below the
     * repository's own. */
    for (size_t i = 0; !err && i < sizeof(levels) / sizeof(levels[0]); i++) {
        git_buf path = GIT_BUF_INIT;
        if (levels[i].find(&path) == 0) err = source_config(config, path.ptr, levels[i].level);
        git_buf_dispose(&path);
    }
    if (!err) err = source_bool(config, "core.ignorecase", &ignorecase);
    if (!err) err = source_string(f, config, "core.excludesfile", &excludesfile);
    git_config_free(config);

    if (err) {
        r->failure = err;
        return r;
    }

    /* The workdir, in git's order. The two keys are the format's: a config that
     * declares none names no layout (setup.c read_repository_format keeps nothing
     * it read), and a gitdir with a common dir of its own — a linked worktree —
     * takes none from the common config unless the worktree's own is read. Both
     * at once is git's refusal (setup.c apply_repository_format: "core.bare and
     * core.worktree do not make sense"), and so is a core.worktree that names
     * nothing — empty, it names nothing as git's chdir("") does. */
    if (!version || (commondir != gitdir && !worktree_config)) {
        r->workdir = found;
    } else if (worktree && bare) {
        r->failure = ERROR(
            ERR_VALIDATION, "'%s' sets both core.bare and core.worktree, which do not make sense",
            gitdir
        );
        return r;
    } else if (worktree) {
        r->workdir = source_resolve(
            f, *worktree && *worktree != '/'
                ? arena_str_format(f->arena, "%s%s", gitdir, worktree) : worktree
        );
        if (!r->workdir) {
            r->failure = error_from_errno(
                errno, "Failed to resolve core.worktree '%s' of '%s'", worktree, gitdir
            );
            return r;
        }
    } else if (!bare) {
        r->workdir = found;
    }
    if (!r->workdir) return r;

    r->casing = ignorecase ? GITIGNORE_CASE_INSENSITIVE : GITIGNORE_CASE_SENSITIVE;

    /* The two lists after every .gitignore, read now. info/exclude, in the common
     * dir, which a linked worktree shares; and the excludes file, the last. */
    source_read(
        f, arena_str_format(f->arena, "%sinfo/exclude", commondir), 0, r->casing,
        &r->info_exclude
    );
    r->info_exclude.next = &r->excludes_file;

    /* core.excludesFile as git reads a path (config.c git_config_pathname): `~`
     * expanded, relative to the workdir, where git reads it from, and set empty,
     * naming no file. `:(optional)` before it makes a file that is not there
     * the key unset — read as it is where nothing sets it: git's default
     * (environment.c repo_excludes_file, path.c xdg_config_home). */
    bool optional = excludesfile && strncmp(excludesfile, ":(optional)", 11) == 0;
    if (optional) excludesfile += 11;

    if (excludesfile && *excludesfile) {
        const char *path = NULL;
        err = fs_expand_tilde(excludesfile, f->arena, &path);
        if (err) {
            r->excludes_file.failure = error_wrap(err, "Failed to read core.excludesFile");
        } else {
            source_read(
                f, path[0] == '/' ? path : str_path_join(f->arena, r->workdir, path), 0,
                r->casing, &r->excludes_file
            );
        }
    }
    if (!excludesfile || (optional && !r->excludes_file.rules && !r->excludes_file.failure)) {
        const char *xdg = getenv("XDG_CONFIG_HOME");
        source_read(
            f, xdg && *xdg ? str_path_join(f->arena, xdg, "git/ignore")
                           : str_path_join(f->arena, identity()->home, ".config/git/ignore"),
            0, r->casing, &r->excludes_file
        );
    }

    return r;
}

/* ══════════════════════════════════════════════════════════════════
 * Discovery
 * ══════════════════════════════════════════════════════════════════ */

/**
 * GIT_CEILING_DIRECTORIES, as git reads it (setup.c canonicalize_ceiling_entry):
 * each absolute entry through its '/', resolved — or kept as spelled once an
 * empty entry has turned resolving off — and a relative one, or one that resolves
 * to nothing, dropped. NULL where none is left.
 */
static hashmap_t *source_ceilings(arena_t *arena) {
    hashmap_t *ceilings = NULL;
    bool verbatim = false;

    const char *entry = getenv("GIT_CEILING_DIRECTORIES");
    while (entry && *entry) {
        size_t n = strcspn(entry, ":");
        const char *spelled = arena_strndup(arena, entry, n);
        entry += n + (entry[n] == ':');

        /* An empty entry keeps every later one as spelled; a relative one, or
         * one that resolves to nothing, is dropped. */
        if (n == 0) {
            verbatim = true;
            continue;
        }
        if (*spelled != '/') continue;

        char resolved[PATH_MAX];
        const char *ceiling = verbatim ? spelled : realpath(spelled, resolved);
        if (!ceiling) continue;

        size_t len = strlen(ceiling);
        char *key = arena_str_format(arena, "%s%s", ceiling, ceiling[len - 1] == '/' ? "" : "/");
        if (!ceilings) ceilings = hashmap_borrow(arena, 0);
        hashmap_set(ceilings, key, key);
    }

    return ceilings;
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
 * read_gitfile_gently) — and so is a `.git` that is neither a file nor a directory,
 * and a git directory whose commondir names nothing.
 */
static error_t source_discover(
    source_filter_t *f, const char *directory, const repository_t **out
) {
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
        } else {
            /* Neither: git reads a `.git` it can stat as a directory or a file,
             * and refuses anything else ("not a regular file"). */
            return ERROR(ERR_VALIDATION, "'%s.git' is not a regular file", directory);
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
 * repository at it, else its parent's answer, unless its parent is a ceiling or
 * stands on another filesystem, where git's walk up stops (setup.c
 * repo_discovery_find_dir)
 *
 * A directory the invoker cannot look into is one discovery cannot examine: it
 * reads as its parent reads, as libgit2 walks past a level it cannot stat — git
 * itself cannot work there as the invoker at all (sys/source.h). Memoised in
 * the one map every spelling shares, under the kernel's spelling, which the answer
 * keeps: the prefix points into it.
 */
static directory_t *source_place(source_filter_t *f, const char *physical, size_t len) {
    directory_t *d = hashmap_get_n(f->directories, physical, len);
    if (d) return d;

    char *key = arena_strndup(f->arena, physical, len);
    d = arena_calloc(f->arena, 1, sizeof(*d));
    d->physical = key;

    struct stat st;
    const repository_t *repository = NULL;

    int rc = stat(key, &st);
    if (rc == 0) {
        d->dev = st.st_dev;
        d->failure = source_discover(f, key, &repository);
    }

    /* None at this level: the parent's answer, where the walk up may reach it —
     * never into a ceiling, which git never enters from below (a directory that
     * is one still asks its own `.git`), and never across a filesystem unless
     * the environment says so. git compares each level with where its walk began;
     * one level with the next meets the first change as surely. */
    size_t above = source_parent(key, len);
    if (!d->failure && !repository && above && !hashmap_get_n(f->ceilings, key, above)) {
        const directory_t *parent = source_place(f, key, above);
        if (rc != 0) d->dev = parent->dev;
        if (f->across || d->dev == parent->dev) {
            repository = parent->repository;
            d->failure = parent->failure;
        }
    }

    /* Where the directory stands inside the repository's workdir: a suffix of
     * the key, "" at the workdir, nowhere outside it or where there is none. */
    if (repository && !d->failure) {
        d->repository = repository;
        d->failure = repository->failure;

        size_t root = repository->workdir ? strlen(repository->workdir) : 0;
        if (!d->failure && root && strncmp(key, repository->workdir, root) == 0) {
            d->prefix = key + root;
        }
    }

    hashmap_set(f->directories, key, d);
    return d;
}

/**
 * The kernel's spelling of the directory `path`'s first `len` bytes spell, through
 * its '/', into `physical` (2 × PATH_MAX bytes): the nearest directory at or
 * above it that stands, resolved through the funnel — a directory a sudo'd walk
 * entered is one it resolves — and what lies beneath that one, as spelled
 *
 * @return NULL, or why the spelling resolves to nothing
 */
static error_t source_physical(const char *path, size_t len, char *physical) {
    /* realpath's own limit: a spelling past it names nothing the kernel resolves */
    char spelled[PATH_MAX];
    if (len >= sizeof(spelled)) {
        return error_from_errno(ENAMETOOLONG, "Failed to resolve path '%.*s'", (int) len, path);
    }
    memcpy(spelled, path, len);
    spelled[len] = '\0';

    /* Cut back a directory at a time to the nearest one that stands: one frame,
     * however much of the spelling is not made yet. A part not there, or a file
     * where a directory would be, is not made yet (ENOENT, ENOTDIR); anything
     * else is the spelling's failure, and so is a root that does not resolve. */
    size_t stands = len;
    while (!fs_realpath(spelled, physical)) {
        if ((errno != ENOENT && errno != ENOTDIR) || stands == 1) {
            return error_from_errno(errno, "Failed to resolve path '%s'", spelled);
        }
        stands = source_parent(spelled, stands);
        spelled[stands] = '\0';
    }

    /* The part that stands, through its '/', and the rest as spelled: realpath's
     * answer is under PATH_MAX, and so is the rest. */
    size_t n = strlen(physical);
    if (physical[n - 1] != '/') physical[n++] = '/';
    memcpy(physical + n, path + stands, len - stands);
    physical[n + len - stands] = '\0';

    return NULL;
}

/**
 * The answer for the directory `path`'s first `len` bytes spell, through its
 * '/' — its kernel spelling's (source_place), resolved once per spelling
 *
 * A directory that is not there — `ignore --test` asks about a path before it
 * is made — is spelled as it will be once it is, beneath the kernel's spelling
 * of the nearest one that stands, and reads as that one reads until then: git's
 * rules are the path's, whether it stands or not. A spelling that resolves to
 * nothing else is its own failure.
 */
static const directory_t *source_directory(source_filter_t *f, const char *path, size_t len) {
    directory_t *d = hashmap_get_n(f->directories, path, len);
    if (d) return d;

    char physical[2 * PATH_MAX];
    error_t failure = source_physical(path, len, physical);
    if (failure) {
        d = arena_calloc(f->arena, 1, sizeof(*d));
        d->failure = failure;
    } else {
        size_t n = strlen(physical);
        d = source_place(f, physical, n);

        /* A spelling that is its own kernel's is the entry the walk up just made:
         * one key, never two. */
        if (n == len && memcmp(physical, path, n) == 0) return d;
    }

    hashmap_set(f->directories, arena_strndup(f->arena, path, len), d);
    return d;
}

/* ══════════════════════════════════════════════════════════════════
 * The rung
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The rule of `repository`'s stack that excludes `rung` — git's
 * last_matching_pattern_from_lists, the rung spelled from the workdir: the first
 * list with a rule that matches decides, and a file that could not be read answers
 * its failure where it comes in that order.
 */
static error_t source_decide(
    source_filter_t *f, const repository_t *repository, const char *rung, bool is_dir,
    source_rule_t *out
) {
    *out = (source_rule_t){ 0 };

    /* The chain from the rung's own directory: each .gitignore up to the workdir,
     * deepest first, then info/exclude and the excludes file — git pushes those
     * two the other way round and reads its lists last first (dir.c
     * setup_standard_excludes). Each list reads the rung from its own root, a
     * suffix of it, and one that decides is never read past, so no file after
     * it can fail the rung. */
    const char *slash = strrchr(rung, '/');
    size_t root = slash ? (size_t) (slash - rung) + 1 : 0;

    for (const file_t *file = source_gitignore(f, repository, rung, root); file;
        file = file->next) {
        if (file->failure) return file->failure;

        /* A negation decides the rung as surely, and excludes nothing: git's
         * answer is the pattern that excludes, or none (sys/source.h). */
        const gitignore_rule_t *rule = gitignore_ruleset_find(
            file->rules, rung + file->root, is_dir
        );
        if (rule) {
            if (!gitignore_rule_negated(rule)) *out = (source_rule_t){ rule, file->path };
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

    /* git's discovery environment, read once: where the walk up stops, and whether
     * a filesystem boundary is one. A value git refuses to read is every query's
     * failure, as it is every command's to git (git_env_bool). */
    f->ceilings = source_ceilings(arena);
    const char *across = getenv("GIT_DISCOVERY_ACROSS_FILESYSTEM");
    int value = 0;
    if (across && git_config_parse_bool(&value, across) < 0) {
        f->failure = ERROR(
            ERR_VALIDATION, "GIT_DISCOVERY_ACROSS_FILESYSTEM is not a boolean: '%s'", across
        );
    }
    f->across = value != 0;

    return f;
}

error_t source_filter_physical(
    source_filter_t *f, const char *path, size_t len, const char **out
) {
    CHECK_NULL(f);
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_ARG(
        len > 0 && path[0] == '/' && path[len - 1] == '/',
        "source_filter_physical requires a directory spelled absolute, through its '/'"
    );

    /* The directory's answer under this spelling — the same entry every spelling
     * of it shares — and the spelling it was stored under. One that resolves to
     * nothing keeps no spelling, and its failure says why; a failure of discovery
     * leaves the spelling standing, since the directory is where it is either
     * way. */
    const directory_t *d = source_directory(f, path, len);
    *out = d->physical;

    return d->physical ? NULL : d->failure;
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
    if (f->failure) return f->failure;

    const directory_t *d = source_directory(f, path, (size_t) (name - path));
    if (d->failure) return d->failure;
    if (!d->prefix) return NULL;

    return source_decide(f, d->repository, source_rung(f, d->prefix, name), is_dir, out);
}
