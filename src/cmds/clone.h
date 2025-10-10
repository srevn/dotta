/**
 * clone.h - Clone dotta repository command
 */

#ifndef DOTTA_CMD_CLONE_H
#define DOTTA_CMD_CLONE_H

#include "dotta/types.h"

/**
 * Clone options
 */
typedef struct {
    const char *url;          /* Remote URL (required) */
    const char *path;         /* Local path (NULL = auto-generate from URL) */
    bool quiet;               /* Suppress output */
    bool verbose;             /* Verbose output */
} cmd_clone_options_t;

/**
 * Clone dotta repository
 *
 * Clones remote repository and sets up dotta-worktree branch.
 *
 * @param opts Clone options (must not be NULL)
 * @return Error or NULL on success
 */
dotta_error_t *cmd_clone(const cmd_clone_options_t *opts);

#endif /* DOTTA_CMD_CLONE_H */
