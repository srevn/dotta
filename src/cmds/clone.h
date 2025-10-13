/**
 * clone.h - Clone dotta repository command
 */

#ifndef DOTTA_CMD_CLONE_H
#define DOTTA_CMD_CLONE_H

#include "types.h"

/**
 * Clone options
 */
typedef struct {
    const char *url;          /* Remote URL (required) */
    const char *path;         /* Local path (NULL = auto-generate from URL) */
    bool quiet;               /* Suppress output */
    bool verbose;             /* Verbose output */
    bool bootstrap;           /* Auto-run bootstrap scripts after clone */
    bool no_bootstrap;        /* Skip bootstrap execution entirely */
    bool fetch_all;           /* Fetch all remote profiles (hub mode) */
    const char **profiles;    /* Explicit profiles to fetch (NULL = auto-detect) */
    size_t profile_count;     /* Number of explicit profiles */
} cmd_clone_options_t;

/**
 * Clone dotta repository
 *
 * Clones remote repository and sets up dotta-worktree branch.
 *
 * @param opts Clone options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_clone(const cmd_clone_options_t *opts);

#endif /* DOTTA_CMD_CLONE_H */
