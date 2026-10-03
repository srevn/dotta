/**
 * git.c - Git passthrough command
 */

#include "cmds/git.h"

#include <config.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include "base/args.h"
#include "base/error.h"
#include "base/heap.h"
#include "sys/process.h"

/**
 * Run git on the store, as asked
 *
 * No shell between: execvp's argv, so the line reaches git as typed, and every
 * stdio stream — a terminal, a pipe, a redirect — is git's own.
 */
error_t cmd_git(const dotta_ctx_t *ctx, const cmd_git_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    /* The line for execvp: "git" "-C" "<the store>" <the line as typed> NULL.
     * No command at all is git's to answer as well (its usage, status 1), so
     * the line is handed over whatever it holds. */
    int total_args = 3 + opts->arg_count + 1;  /* git + -C + path + args + NULL */
    char **argv = heap_calloc((size_t) total_args, sizeof(char *));

    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = (char *) ctx->config->repo_dir;  /* Cast away const for execvp */

    for (int i = 0; i < opts->arg_count; i++) {
        argv[3 + i] = opts->args[i];
    }

    argv[total_args - 1] = NULL;

    /* Git in the foreground: the terminal is its and its pager's, and so are
     * the keyboard's signals while it runs; the child is the invoker's, so `sudo
     * dotta git` runs git as the user on the user's repository. */
    process_result_t result;
    error_t err = process_foreground(argv, &result);
    free(argv);
    if (err) return err;

    /* A git that could not be run: its errno, beside the status a shell gives a
     * command it could not run — 127 for one no PATH entry holds, 126 for one
     * it found and could not run. */
    if (result.exec_failed) {
        *ctx->exit_code = result.exec_errno == ENOENT ? 127 : 126;
        return error_from_errno(result.exec_errno, "Cannot run git");
    }

    /* Dead of the keyboard's signal: the terminal sent it to dotta too, which
     * ignored it for git's sake, so dotta dies of it now — the status a shell
     * reads is the one git's own death gives (git's rule, and a script's loop
     * stops as it would for git). */
    if (result.signal_num == SIGINT || result.signal_num == SIGQUIT) {
        raise(result.signal_num);
    }

    /* The status git ended with, as a shell reads it — 128 and the signal for a
     * death. A broken pipe is that status alone: a pager or a `| head` closed
     * it, and git says nothing of its own child's (lib/git/run-command.c
     * wait_or_whine). Any other death is said in git's words for one. */
    *ctx->exit_code = result.exit_code;
    if (result.signal_num != 0 && result.signal_num != SIGPIPE) {
        return error_create(ERR_GIT, "git died of signal %d", result.signal_num);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Passthrough dispatch: the engine hands us the full argv untouched.
 *
 * The line after `git` is the passthrough's options, and git's own status is
 * the run's: `git diff --exit-code`, merge-base probes and CI scripts branch on
 * it, so it is written through `*ctx->exit_code`, and an error rides beside it
 * (include/runtime.h "Exit-code override").
 */
static error_t git_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    (void) opts_v;
    const cmd_git_options_t opts = {
        .args      = &ctx->argv[2],
        .arg_count = ctx->argc - 2,
    };
    return cmd_git(ctx, &opts);
}

const args_command_t spec_git = {
    .name        = "git",
    .summary     = "Execute git commands within repository",
    .dispatch    = git_dispatch,
    .passthrough = true,
};
