/**
 * git.c - Git passthrough command
 */

#include "cmds/git.h"

#include <config.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/error.h"
#include "base/heap.h"
#include "sys/process.h"

/**
 * Execute git command with passthrough
 *
 * Runs git in the foreground (sys/process.h process_foreground) for a secure,
 * full-featured passthrough:
 * - No shell injection vulnerabilities
 * - Preserves all stdio streams (including interactive mode)
 * - Returns git's actual exit code, and dies of the keyboard signal git died of
 * - Works with pipes and redirects
 */
int cmd_git(const char *repo_path, const cmd_git_options_t *opts) {
    CHECK_NULL(repo_path);
    CHECK_NULL(opts);

    if (!opts->args || opts->arg_count == 0) {
        fprintf(stderr, "Error: No git command specified\n\n");
        fprintf(stderr, "Usage: dotta git <git-command> [args...]\n\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  dotta git log global --oneline\n");
        fprintf(stderr, "  dotta git show global:home/.bashrc\n");
        fprintf(stderr, "  dotta git reflog global\n");
        fprintf(stderr, "  dotta git remote -v\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "The git command will be executed in the dotta repository,\n");
        fprintf(stderr, "a bare one: name a profile where git would read HEAD.\n");
        return 1;
    }

    /* Build argv for execvp Format: "git" "-C" "<repo-path>" <user-args...> NULL */
    int total_args = 3 + opts->arg_count + 1;  /* git + -C + path + args + NULL */
    char **argv = heap_calloc((size_t) total_args, sizeof(char *));

    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = (char *) repo_path;  /* Cast away const for execvp */

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
    if (err) {
        fprintf(stderr, "Error: %s\n", error_message(err));
        return 1;
    }

    /* A git that could not be run: its errno, and the status a shell gives a
     * command it could not run — 127 for one no PATH entry holds, 126 for one
     * it found and could not run. */
    if (result.exec_failed) {
        fprintf(stderr, "Error: Cannot run git: %s\n", strerror(result.exec_errno));
        return result.exec_errno == ENOENT ? 127 : 126;
    }

    /* Dead of the keyboard's signal: the terminal sent it to dotta too, which
     * ignored it for git's sake, so dotta dies of it now — the status a shell
     * reads is the one git's own death gives (git's rule, and a script's loop
     * stops as it would for git). */
    if (result.signal_num == SIGINT || result.signal_num == SIGQUIT) {
        raise(result.signal_num);
    }

    /* Killed by anything else: said, and the standard convention's status. */
    if (result.signal_num) {
        fprintf(stderr, "git terminated by signal %d\n", result.signal_num);
    }

    return result.exit_code;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Passthrough dispatch: the engine hands us the full argv untouched.
 *
 * Exit-code preservation: `cmd_git` returns git's own status (0, 1, 2, 128+n).
 * That status IS the user-visible contract — `git diff --exit-code`, merge-base
 * probes, CI scripts all branch on it. We can't funnel it through `error_t` (which
 * collapses to 0 or 1), so we write through `*ctx->exit_code`; `run_spec` honors
 * that when dispatch returns NULL. See `struct args_ctx` docs for the channel.
 */
static error_t git_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    (void) opts_v;
    cmd_git_options_t opts = {
        .args      = &ctx->argv[2],
        .arg_count = ctx->argc - 2,
    };
    *ctx->exit_code = cmd_git(ctx->config->repo_dir, &opts);
    return NULL;
}

const args_command_t spec_git = {
    .name        = "git",
    .summary     = "Execute git commands within repository",
    .usage       = "%s git <git-command> [args...]",
    .description =
        "Pure passthrough to git, scoped to the dotta repository.\n"
        "No interception or modification — all standard git commands and\n"
        "options are supported. Git's exit status is preserved verbatim\n"
        "so scripts depending on codes like 1 (diffs found) or 128\n"
        "(fatal) continue to work under `dotta git`.\n"
        "\n"
        "The repository is bare: nothing is checked out, and HEAD names\n"
        "no profile. Name the profile where git would read HEAD. To look\n"
        "at one with your own tools: `%s git worktree add <dir> <profile>`.\n",
    .examples    =
        "  %s git log global --oneline\n"
        "  %s git show global:home/.bashrc\n"
        "  %s git reflog global\n"
        "  %s git remote -v\n",
    .dispatch    = git_dispatch,
    .passthrough = true,
};
