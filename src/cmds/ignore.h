/**
 * ignore.h - Manage ignore patterns
 *
 * Edit, view, and test ignore patterns across all layers.
 */

#ifndef DOTTA_CMD_IGNORE_H
#define DOTTA_CMD_IGNORE_H

#include <git2.h>

#include "types.h"

/**
 * Command options
 */
typedef struct {
    const char *profile;        /* Profile name (NULL for baseline or all profiles) */
    const char *test_path;      /* Path to test (NULL for edit mode) */
    bool verbose;               /* Print verbose output */
} cmd_ignore_options_t;

/**
 * Manage ignore patterns
 *
 * Allows editing, viewing, and testing ignore patterns.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_ignore(git_repository *repo, const cmd_ignore_options_t *opts);

#endif /* DOTTA_CMD_IGNORE_H */
