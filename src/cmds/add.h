/**
 * add.h - Add files to profiles
 *
 * Adds files to git profile branches using temporary worktrees.
 */

#ifndef DOTTA_CMD_ADD_H
#define DOTTA_CMD_ADD_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char *profile;        /* Profile name (required) */
    const char **files;         /* Array of file paths (required) */
    size_t file_count;          /* Number of files */
    const char *message;        /* Commit message (optional) */
    char **exclude_patterns;    /* Exclude patterns (glob) - read-only */
    size_t exclude_count;       /* Number of exclude patterns */
    bool force;                 /* Overwrite existing files in profile */
    bool verbose;               /* Print verbose output */
    bool encrypt;               /* Force encryption (--encrypt flag) */
    bool no_encrypt;            /* Force no encryption (--no-encrypt flag) */
} cmd_add_options_t;

/**
 * Add files to a profile
 *
 * Uses temporary worktree to safely add files to a profile branch.
 * Creates the profile branch if it doesn't exist.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_add(git_repository *repo, const cmd_add_options_t *opts);

#endif /* DOTTA_CMD_ADD_H */
