/**
 * repo.h - The store: where it is, what makes it one, how it is opened
 *
 * dotta's store is a bare Git repository — one branch per profile under refs/heads,
 * the epoch and this machine's baseline under refs/dotta, the record (`dotta.db`)
 * at its root — that dotta made or took, and declared its own. Nothing is ever
 * checked out: every write to a branch is a stage committed in memory (sys/stage),
 * and HEAD is git's alone, written once by the init and never read (sys/gitops.h,
 * gitops_init_repository).
 *
 * Where it is, this machine decides, and the configuration settles it once, at
 * load (utils/config.h config_load): DOTTA_REPO_DIR where it is set, else [core]
 * repo_dir, else ~/.local/share/dotta/repo — absolute and folded, in
 * `config->repo_dir`. This is different from git's behavior - dotta uses a
 * centralized repository, not discovery from current working directory.
 *
 * What makes a directory the store is a fact its maker writes into the store's
 * own config, the way git writes `core.bare`:
 *
 *     [dotta] store = true
 *
 * Nothing structural could carry it. The epoch is deletable by design (a change
 * of strength is a new epoch) and its absence a state `sync` heals from the remote;
 * the baseline is this machine's and re-seeded; the record is disposable (a fresh
 * machine on a known store has none). A bare repository alone is any bare
 * repository, and a mirror at DOTTA_REPO_DIR would be committed into. So the
 * maker declares (repo_declare_store) and the opener reads the declaration
 * (repo_is_store, repo_open): the local-side counterpart of the epoch's role on
 * the remote side, where `dotta clone` gates on the ref being advertised.
 *
 * Which *directory* the store is is `git_repository_path` on the open handle
 * and not `config->repo_dir`: the two name one directory for the bare repository
 * dotta makes and two for a non-bare one a hand declared, where the store's own
 * files sit in the `.git/` and the path resolves to the worktree beside it. One
 * reader — core/state.c get_db_path, joining the database onto it.
 */

#ifndef DOTTA_REPO_H
#define DOTTA_REPO_H

#include <git2.h>
#include <types.h>

/**
 * Where a create-style command puts the repository
 *
 * `config->repo_dir` answers "where does this machine's repository live"; this
 * answers "where does a command that creates one put it". Two questions, two
 * tails: only the second has a positional to honour, parent directories to make,
 * and a caller to warn.
 *
 * `explicit_path` is the command's optional positional (`init [path]`, `clone
 * <url> [path]`); NULL means "wherever this machine's repository lives", which
 * is `config->repo_dir` and nothing else. Both are read by one function
 * (sys/filesystem.h fs_make_absolute: `~` expanded, a relative path settled against
 * the current directory, the whole folded where the kernel reads the fold the
 * same), and both get their parent directories — an explicit path is not a lesser
 * path, and each of the two commands used to drop a different step: a quoted
 * `dotta init "~/dotfiles"` created a literal `./~/dotfiles`, and `dotta clone`
 * re-derived the implicit branch without $DOTTA_REPO_DIR in it.
 *
 * `*out_elsewhere` is where later commands will look, set only when that is not
 * `*out_path` — NULL when the two are the same place, so a non-NULL answer is
 * exactly "this repository is somewhere dotta will not find it". Both sides are
 * read by that one function, which is what makes the comparison mean anything:
 * `./repo`, `repo/` and the configured spelling of one directory are one string.
 * The caller says so on success, because nothing else will: every later command
 * resolves the configured location and stops there, so a `dotta status` run
 * straight afterwards answers "No dotta repository found... Run 'dotta init'"
 * about the repository just created.
 *
 * @param config        Loaded configuration (must not be NULL)
 * @param arena         Arena a positional's settled spelling lives in (must not
 *                      be NULL); the configured location is the configuration's,
 *                      the process's, so either answer outlives the command
 * @param explicit_path The command's positional, or NULL for the configured
 *                      location
 * @param out_path      Resolved absolute path (must not be NULL)
 * @param out_elsewhere Optional: the configured location when out_path is not
 *                      it, NULL otherwise (can be NULL)
 * @return Error or NULL on success
 */
error_t repo_create_target(
    const config_t *config,
    arena_t *arena,
    const char *explicit_path,
    const char **out_path,
    const char **out_elsewhere
);

/**
 * Declare the repository dotta's store
 *
 * Writes the marker (the header) into the repository's own config, and beside
 * it `core.logAllRefUpdates = true`: a bare repository keeps no reflog by default,
 * and `dotta git reflog <profile>` is a screen the store has always had. Written
 * by the two makers on every path through — init over a fresh store, over one
 * it takes (bare, no refs at all) and over its own again; clone over the store
 * it just created — so a store is declared from birth and a repaired one is
 * declared again. Idempotent.
 *
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t repo_declare_store(git_repository *repo);

/**
 * Is this repository declared dotta's store?
 *
 * The marker `repo_declare_store` writes, read at the LOCAL config level only —
 * the store's own file, never the user's global config, where a `dotta.store`
 * would declare every repository on the machine (pinned: the layered handle reads
 * it through). Two callers, two uses of the answer: `repo_open` refuses on false;
 * init takes a bare repository on true and looks at its refs on false — and asks
 * this first, since the bareness it then trusts is a value of the same file
 * (cmds/init.c ensure_repository_adoptable).
 *
 * A store whose config file cannot be read is not "not a store": libgit2 drops
 * the local level when the file will not open — access(2) refused it, or it is
 * a directory; a missing file still yields an empty level — and reports the drop
 * as GIT_ENOTFOUND, and that one is refused naming the file, in the kernel's
 * word. A value that is not a boolean is Git's own error.
 *
 * @param repo Repository (must not be NULL)
 * @param out Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t repo_is_store(git_repository *repo, bool *out);

/**
 * Open dotta's store
 *
 * Opens the store's directory the configuration settled (`config->repo_dir`),
 * and reads its declaration (repo_is_store): a repository that does not carry
 * one is somebody's — a project with a working tree, a mirror, the checked-out
 * store an older dotta kept — and refused with ERR_NOT_FOUND naming the path,
 * and DOTTA_REPO_DIR where the path came from it. This is the standard way to
 * open the store for dotta commands — the pass-through (`dotta git`) is the one
 * that deliberately does not, forking git over the settled directory itself
 * (cmds/git.h).
 *
 * THE OPEN IS THE PRESENCE TEST: there is no separate "is a repository here"
 * question — asking it means opening, and a predicate that opens and throws the
 * failure away reports "absent" for every reason an open can fail. So the open's
 * own failure is what gets classified, and only the one case that is genuinely
 * an absence is reworded:
 *
 * - ERR_NOT_FOUND — the path holds no repository: nothing there, an empty
 *   directory, a directory of other things, a store a hand stripped of its HEAD
 *   (which `dotta init` recreates with refs, epoch and record intact) — the open's
 *   own proof (sys/gitops.h gitops_open_repository). The same code, its own words,
 *   for a repository that opened and is not declared the store.
 * - ERR_GIT — a repository is there and could not be read: one libgit2 would
 *   not open whose HEAD stands, a directory the open could not look into, a config
 *   file that will not parse, a damaged object database — the cause's own words
 *   wrapped beneath the path, never replaced.
 * - ERR_PERMISSION — the repository is owned by another user, its owner check's
 *   own words beneath the path.
 *
 * Every refusal names the path, and DOTTA_REPO_DIR where the path came from it.
 *
 * OWNERSHIP:
 * - Caller must free repository with git_repository_free()
 * - On error, the output is not modified
 *
 * @param config Loaded configuration (must not be NULL)
 * @param repo_out Repository handle (must not be NULL, caller must free)
 * @return Error or NULL on success
 */
error_t repo_open(const config_t *config, git_repository **repo_out);

#endif /* DOTTA_REPO_H */
