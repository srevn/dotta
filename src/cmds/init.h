/**
 * init.h - Initialize dotta repository
 *
 * Creates a new dotta repository with initial branch structure.
 */

#ifndef DOTTA_CMD_INIT_H
#define DOTTA_CMD_INIT_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char *repo_path;   /* Repository path (NULL = current dir) */
    bool quiet;              /* Suppress output */
} cmd_init_options_t;

/**
 * Initialize a dotta repository
 *
 * Creates or opens a git repository and sets up dotta branch structure.
 * Creates initial empty state file.
 *
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_init(const cmd_init_options_t *opts);

#endif /* DOTTA_CMD_INIT_H */
