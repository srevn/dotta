/**
 * diff.h - Show differences between profiles and filesystem
 *
 * Displays actual content differences for modified files.
 *
 * Direction semantics:
 * - Upstream (repository): Source of truth for configuration
 * - Downstream (filesystem): Deployed state
 *
 * DIFF_UPSTREAM: Shows repo → filesystem (what 'apply' would change)
 * DIFF_DOWNSTREAM: Shows filesystem → repo (what 'update' would commit)
 * DIFF_BOTH: Shows both directions
 */

#ifndef DOTTA_CMD_DIFF_H
#define DOTTA_CMD_DIFF_H

#include <git2.h>

#include "dotta/types.h"

/**
 * Diff direction
 */
typedef enum {
    DIFF_UPSTREAM,      /* Show changes from repo to filesystem (default) */
    DIFF_DOWNSTREAM,    /* Show changes from filesystem to repo */
    DIFF_BOTH           /* Show both directions */
} diff_direction_t;

/**
 * Command options
 */
typedef struct {
    const char **files;         /* Specific files to diff (NULL = all) */
    size_t file_count;          /* Number of files */
    const char **profiles;      /* Profile names (NULL = auto-detect) */
    size_t profile_count;       /* Number of profiles */
    bool name_only;             /* Only show file names, not diffs */
    bool all_changes;           /* Show all changed files (deprecated, use direction) */
    diff_direction_t direction; /* Which direction to show */
} cmd_diff_options_t;

/**
 * Show differences
 *
 * Compares files in profiles with their deployed versions.
 *
 * @param repo Repository (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
dotta_error_t *cmd_diff(git_repository *repo, const cmd_diff_options_t *opts);

#endif /* DOTTA_CMD_DIFF_H */
