/**
 * git.h - Git passthrough command
 *
 * Provides direct access to git commands within the dotta repository. For advanced
 * users who need low-level git operations.
 */

#ifndef DOTTA_CMD_GIT_H
#define DOTTA_CMD_GIT_H

#include <runtime.h>

/**
 * Git command options
 */
typedef struct {
    char **args;         /* Git arguments (excluding 'git' itself) */
    int arg_count;       /* Number of arguments */
} cmd_git_options_t;

/**
 * Git command implementation
 *
 * Executes git commands directly on the dotta repository. Pure passthrough - no
 * interception or modification.
 *
 * @param repo_path The store's directory (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Exit code from git (0 = success, non-zero = error)
 */
int cmd_git(const char *repo_path, const cmd_git_options_t *opts);

/**
 * Spec-engine command specification for `dotta git`.
 *
 * Passthrough, and nothing declared: the engine skips argv parsing entirely and
 * the dispatcher opens nothing; cmd_git forks git over the store's directory
 * the configuration settled (`config->repo_dir`). Never opened here, because an
 * open is dotta asserting its own model of the repository — libgit2's open, which
 * reads files of the user's that dotta itself commonly deploys (~/.gitconfig)
 * and can refuse over one of them, and then the store's own declaration
 * (utils/repo.h). The pass-through is what a user reaches for when that model
 * does not hold — `dotta git show global:home/.gitconfig` is the way back to
 * the committed copy of the file that broke the open — so it cannot be gated on
 * the model holding: an opening pass-through would answer that remedy with the
 * very error the remedy is for.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in git.c beside the
 * dispatch wrapper.
 */
extern const args_command_t spec_git;

#endif /* DOTTA_CMD_GIT_H */
