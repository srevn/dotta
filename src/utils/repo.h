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
 * Where it is, this machine decides:
 * 1. DOTTA_REPO_DIR environment variable (highest priority)
 * 2. Config file setting (~/.config/dotta/config.toml)
 * 3. Default location: ~/.local/share/dotta/repo
 *
 * This is different from git's behavior - dotta uses a centralized repository,
 * not discovery from current working directory.
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
 * and not `resolve_repo_path`: the two name one directory for the bare repository
 * dotta makes and two for a non-bare one a hand declared, where the store's own
 * files sit in the `.git/` and the path resolves to the worktree beside it. One
 * reader — core/state.c get_db_path, joining the database onto it.
 */

#ifndef DOTTA_REPO_H
#define DOTTA_REPO_H

#include <git2.h>
#include <types.h>

/**
 * Resolve repository path
 *
 * Determines the dotta repository location based on:
 * 1. DOTTA_REPO_DIR environment variable (always highest priority)
 * 2. Config file repo_dir setting
 * 3. Default: ~/.local/share/dotta/repo
 *
 * The path is always expanded (~ becomes absolute path). If the config file exists
 * but fails to parse/validate, a warning is emitted to stderr and the resolution
 * continues without config (env var and default are still respected).
 *
 * @param config Loaded configuration (must not be NULL)
 * @param out Resolved repository path (caller must free)
 * @return Error or NULL on success
 */
error_t *resolve_repo_path(const config_t *config, char **out);

/**
 * Where a create-style command puts the repository
 *
 * `resolve_repo_path` answers "where does this machine's repository live"; this
 * answers "where does a command that creates one put it". Two questions, two
 * tails: only the second has a positional to honour, parent directories to make,
 * and a caller to warn.
 *
 * `explicit_path` is the command's optional positional (`init [path]`, `clone
 * <url> [path]`); NULL means "wherever this machine's repository lives", which
 * is `resolve_repo_path` and nothing else. Both branches expand `~`, settle a
 * relative path against the current directory, and create the parent directories
 * — an explicit path is not a lesser path, and each of the two commands used to
 * drop a different one of those three steps: a quoted `dotta init "~/dotfiles"`
 * created a literal `./~/dotfiles`, and `dotta clone` re-derived the implicit
 * branch without $DOTTA_REPO_DIR in it.
 *
 * `*out_elsewhere` is where later commands will look, set only when that is not
 * `*out_path` — NULL when the two are the same place, so a non-NULL answer is
 * exactly "this repository is somewhere dotta will not find it". Both sides are
 * normalised here, by one function, which is what makes the comparison mean
 * anything. The caller says so on success, because nothing else will: every later
 * command resolves the configured location and stops there, so a `dotta status`
 * run straight afterwards answers "No dotta repository found... Run 'dotta init'"
 * about the repository just created.
 *
 * @param config        Loaded configuration (must not be NULL)
 * @param explicit_path The command's positional, or NULL for the configured
 *                      location
 * @param out_path      Resolved absolute path (must not be NULL, caller frees)
 * @param out_elsewhere Optional: the configured location when out_path is not
 *                      it, NULL otherwise (can be NULL; caller frees)
 * @return Error or NULL on success
 */
error_t *repo_create_target(
    const config_t *config,
    const char *explicit_path,
    char **out_path,
    char **out_elsewhere
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
error_t *repo_declare_store(git_repository *repo);

/**
 * Is this repository declared dotta's store?
 *
 * The marker `repo_declare_store` writes, read at the LOCAL config level only —
 * the store's own file, never the user's global config, where a `dotta.store`
 * would declare every repository on the machine (pinned: the layered handle reads
 * it through). Two callers, two uses of the answer: `repo_open` refuses on false;
 * init takes the repository on true and looks at its refs on false.
 *
 * A store whose config file cannot be read is not "not a store": libgit2 drops
 * the local level when the file will not open (a missing file still yields an
 * empty level) and reports the drop as GIT_ENOTFOUND, and that one is returned
 * as the error it is. A value that is not a boolean is Git's own error.
 *
 * @param repo Repository (must not be NULL)
 * @param out Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *repo_is_store(git_repository *repo, bool *out);

/**
 * Open dotta's store
 *
 * Resolves the store's path, opens it, and reads its declaration (repo_is_store):
 * a repository that does not carry one is somebody's — a project with a working
 * tree, a mirror, the checked-out store an older dotta kept — and refused with
 * ERR_NOT_FOUND naming the path, `dotta init` and DOTTA_REPO_DIR. This is the
 * standard way to open the store for dotta commands — the pass-through (`dotta
 * git`) is the one that deliberately does not, taking only the path
 * (`dotta_repo_mode_t` in include/runtime.h).
 *
 * RESOLUTION ORDER:
 * 1. DOTTA_REPO_DIR environment variable
 * 2. Config file repo_dir setting
 * 3. Default: ~/.local/share/dotta/repo
 *
 * THE OPEN IS THE PRESENCE TEST: there is no separate "is a repository here"
 * question — asking it means opening, and a predicate that opens and throws the
 * failure away reports "absent" for every reason an open can fail. So the open's
 * own failure is what gets classified, and only the one case that is genuinely
 * an absence is reworded:
 *
 * - ERR_NOT_FOUND — the path holds no repository: nothing there, an empty
 *   directory, a directory of other things, a store a hand stripped of its HEAD
 *   (which `dotta init` recreates with refs, epoch and record intact). Names
 *   the path, the hint to run 'dotta init', and DOTTA_REPO_DIR when the path
 *   came from it. The same code, its own words, for a repository that opened
 *   and is not declared the store.
 * - ERR_GIT — a repository is there and libgit2 could not read it (the same
 *   GIT_ENOTFOUND, told apart by the filesystem: the store is the directory,
 *   and its HEAD present or unstattable is a store dotta cannot look into), or
 *   the open failed for its own reason — a config file that will not parse, a
 *   damaged object database — in which case libgit2's message is wrapped, not
 *   replaced.
 * - ERR_PERMISSION — the repository is owned by another user.
 *
 * OWNERSHIP:
 * - Caller must free repository with git_repository_free()
 * - Caller must free path_out (if requested) with free()
 * - On error, outputs are not modified
 *
 * @param config Loaded configuration (must not be NULL)
 * @param repo_out Repository handle (must not be NULL, caller must free)
 * @param path_out Optional resolved path (can be NULL, caller must free if set)
 * @return Error or NULL on success
 */
error_t *repo_open(const config_t *config, git_repository **repo_out, char **path_out);

#endif /* DOTTA_REPO_H */
