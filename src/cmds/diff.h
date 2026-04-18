/**
 * diff.h - Show differences between profiles and filesystem
 *
 * Displays actual content differences for modified files.
 *
 * Direction semantics (unified diff representation):
 * - DIFF_UPSTREAM:   old=filesystem, new=repo  — '-' lines are current on disk,
 *                    '+' lines are what apply would write. Use to preview apply.
 * - DIFF_DOWNSTREAM: old=repo, new=filesystem  — '-' lines are in repo,
 *                    '+' lines are local changes. Use to preview update.
 * - DIFF_BOTH:       Shows both directions with labelled sections.
 */

#ifndef DOTTA_CMD_DIFF_H
#define DOTTA_CMD_DIFF_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

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
 *
 * Numeric 0 is reserved as the "unset" sentinel so post_parse can
 * detect whether the user supplied an explicit direction flag. The
 * three real directions are written by ARGS_FLAG_SET rows; post_parse
 * maps unset→UPSTREAM after validating mode compatibility.
 */
typedef enum {
    DIFF_DIR_UNSET = 0,  /* Internal sentinel (no flag seen yet). */
    DIFF_UPSTREAM,       /* old=filesystem, new=repo (apply preview). */
    DIFF_DOWNSTREAM,     /* old=repo, new=filesystem (update preview). */
    DIFF_BOTH            /* Show both directions in labelled sections. */
} diff_direction_t;

/**
 * Command options
 *
 * `mode`, `commit1`, `commit2` are derived by `diff_post_parse` from
 * the three classified positional buckets (git refs, files, profiles).
 * `direction == DIFF_DIR_UNSET` (0) signals "no direction flag was
 * supplied" so post_parse can reject a direction in commit modes.
 */
typedef struct {
    /* User-facing (read by cmd_diff) */
    diff_mode_t mode;           /* Diff mode */
    char **files;               /* Workspace diff: file filters */
    size_t file_count;          /* Number of files */
    int direction;              /* Which direction to show */
    const char *commit1;        /* First commit (old) */
    const char *commit2;        /* Second commit (new, NULL = workspace) */
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    bool name_only;             /* Only show file names, not diffs */
    char **git_refs;            /* Classified git-ref positionals */
    size_t git_ref_count;
} cmd_diff_options_t;

/**
 * Show differences
 *
 * Compares files in profiles with their deployed versions.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_diff(const dotta_ctx_t *ctx, const cmd_diff_options_t *opts);

/**
 * Spec-engine command specification for `dotta diff`.
 *
 * Registered in cmds/registry.c. Defined in diff.c beside the
 * classifier, post_parse, and dispatch wrappers.
 */
extern const args_command_t spec_diff;

#endif /* DOTTA_CMD_DIFF_H */
