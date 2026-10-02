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
 * Run git on the store, as asked
 *
 * A passthrough: git -C <the store's directory> and the line as typed, in the
 * foreground (sys/process.h process_foreground). What the line holds is git's
 * to answer — no command at all included: git's usage, status 1 (lib/git/git.c
 * cmd_main). The run's status is git's own (*ctx->exit_code), as a shell reads
 * it, and so is its death: by the keyboard's signal dotta dies too, and by a
 * broken pipe — a pager or a `| head` closed early — the status alone, as git
 * says nothing of its own children's (lib/git/run-command.c wait_or_whine).
 *
 * A refusal is returned beside the status the run ends with: a process that could
 * not be started; a git that could not be run, 127 where no PATH entry holds
 * one and 126 where one was found and not run (a shell's statuses); a git that
 * died of another signal, 128 and the signal (include/runtime.h "Exit-code
 * override").
 *
 * @param ctx The run: the store's directory (ctx->config) and the status
 *            (ctx->exit_code) (must not be NULL)
 * @param opts The line after `git` (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_git(const dotta_ctx_t *ctx, const cmd_git_options_t *opts);

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
