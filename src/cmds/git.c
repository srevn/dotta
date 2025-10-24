/**
 * git.c - Git passthrough command
 */

#include "git.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

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
    if (!repo_path || !opts || !opts->args || opts->arg_count == 0) {
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
    char **argv = malloc((size_t)total_args * sizeof(char *));
    if (!argv) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        return 1;
    }

    argv[0] = "git";
    argv[1] = "-C";
    argv[2] = (char *)repo_path;  /* Cast away const for execvp */

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
        /* Child process: execute git */
        execvp("git", argv);

        /* If we get here, exec failed */
        perror("execvp: git");
        exit(127);  /* Standard exit code for command not found */
    }

    /* Parent process: wait for git to complete */
    free(argv);

    int status;
    pid_t wait_result = waitpid(pid, &status, 0);

    if (wait_result < 0) {
        perror("waitpid");
        return 1;
    }

    /* Return git's exit code */
    printf("\n");

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        /* Git was killed by signal */
        fprintf(stderr, "git terminated by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);  /* Standard convention */
    }

    return 1;
}
