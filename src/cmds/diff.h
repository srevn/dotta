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

#include "types.h"

/**
 * Diff mode
 */
typedef enum {
    DIFF_WORKSPACE,           /* Workspace diff: profile ↔ filesystem (default) */
    DIFF_COMMIT_TO_COMMIT,    /* Compare two commits */
    DIFF_COMMIT_TO_WORKSPACE  /* Compare commit to workspace */
} diff_mode_t;

/**
 * Diff direction (for workspace mode only)
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
    diff_mode_t mode;           /* Diff mode */

    /* For workspace diff (DIFF_WORKSPACE) */
    char **files;               /* Specific files to diff (NULL = all) */
    size_t file_count;          /* Number of files */
    diff_direction_t direction; /* Which direction to show */

    /* For commit diff (DIFF_COMMIT_TO_COMMIT, DIFF_COMMIT_TO_WORKSPACE) */
    const char *commit1;        /* First commit (old) */
    const char *commit2;        /* Second commit (new, NULL = workspace) */

    /* Common options */
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    bool name_only;             /* Only show file names, not diffs */
    bool all_changes;           /* Show all changed files (deprecated, use direction) */
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
error_t *cmd_diff(git_repository *repo, const cmd_diff_options_t *opts);

#endif /* DOTTA_CMD_DIFF_H */
