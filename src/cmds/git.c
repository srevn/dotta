/**
 * git.c - Git passthrough command
 */

#include "cmds/git.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/args.h"

/**
 * Execute git command with passthrough
 *
 * Uses fork+exec for secure, full-featured passthrough:
 * - No shell injection vulnerabilities
 * - Preserves all stdio streams (including interactive mode)
 * - Returns git's actual exit code
 * - Works with pipes and redirects
 */
int cmd_git(const char *repo_path, const cmd_git_options_t *opts) {
    if (!repo_path || !opts) {
        fprintf(stderr, "Error: Internal error (NULL arguments)\n");
        return 1;
    }

    if (!opts->args || opts->arg_count == 0) {
        fprintf(stderr, "Error: No git command specified\n\n");
        fprintf(stderr, "Usage: dotta git <git-command> [args...]\n\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  dotta git status\n");
        fprintf(stderr, "  dotta git log --oneline\n");
        fprintf(stderr, "  dotta git show HEAD:home/.bashrc\n");
        fprintf(stderr, "  dotta git reflog\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "The git command will be executed in the dotta repository.\n");
        fprintf(stderr, "All standard git commands and options are supported.\n");
        return 1;
    }

    /* Build argv for execvp
     * Format: "git" "-C" "<repo-path>" <user-args...> NULL
     */
    int total_args = 3 + opts->arg_count + 1;  /* git + -C + path + args + NULL */
    char **argv = malloc((size_t) total_args * sizeof(char *));
    if (!argv) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        return 1;
    }

    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = (char *) repo_path;  /* Cast away const for execvp */

    for (int i = 0; i < opts->arg_count; i++) {
        argv[3 + i] = opts->args[i];
    }

    argv[total_args - 1] = NULL;

    /* Fork and execute */
    pid_t pid = fork();

    if (pid < 0) {
        /* Fork failed */
        perror("fork");
        free(argv);
        return 1;
    }

    if (pid == 0) {
        /* Child process: execute git
         * argv is intentionally not freed - execvp replaces the process image,
         * and _exit() bypasses cleanup on failure */
        execvp("git", argv);

        /* If we get here, exec failed
         * Use _exit() to avoid flushing parent's stdio buffers
         * and running parent's atexit handlers */
        perror("execvp: git");
        _exit(127);
    }

    /* Parent process: wait for git to complete */
    free(argv);

    int status;
    pid_t wait_result;
    while ((wait_result = waitpid(pid, &status, 0)) == -1) {
        if (errno != EINTR) {
            perror("waitpid");
            return 1;
        }
        /* EINTR: signal interrupted wait, retry */
    }

    /* Return git's exit code */
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        /* Git was killed by signal */
        fprintf(stderr, "git terminated by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);  /* Standard convention */
    }

    return 1;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Passthrough dispatch: the engine hands us the full argv untouched.
 *
 * Exit-code preservation: `cmd_git` returns git's own status (0, 1, 2,
 * 128+n). That status IS the user-visible contract — `git diff
 * --exit-code`, merge-base probes, CI scripts all branch on it. We
 * can't funnel it through `error_t *` (which collapses to 0 or 1), so
 * we write through `*ctx->exit_code`; `run_spec` honors that when
 * dispatch returns NULL. See `struct args_ctx` docs for the channel.
 */
static error_t *git_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    (void) opts_v;
    cmd_git_options_t opts = {
        .args      = &ctx->argv[2],
        .arg_count = ctx->argc - 2,
    };
    *ctx->exit_code = cmd_git(ctx->repo_path, &opts);
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
        "(fatal) continue to work under `dotta git`.\n",
    .examples    =
        "  %s git status\n"
        "  %s git log --oneline\n"
        "  %s git show HEAD:home/.bashrc\n"
        "  %s git reflog\n",
    .payload     = &dotta_ext_path_only,
    .dispatch    = git_dispatch,
    .passthrough = true,
};
