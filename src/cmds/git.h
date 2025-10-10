/**
 * git.h - Git passthrough command
 *
 * Provides direct access to git commands within the dotta repository.
 * For advanced users who need low-level git operations.
 */

#ifndef DOTTA_CMD_GIT_H
#define DOTTA_CMD_GIT_H

#include "dotta/types.h"

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
 * Executes git commands directly on the dotta repository.
 * Pure passthrough - no interception or modification.
 *
 * @param repo_path Repository path (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Exit code from git (0 = success, non-zero = error)
 */
int cmd_git(const char *repo_path, const cmd_git_options_t *opts);

#endif /* DOTTA_CMD_GIT_H */
