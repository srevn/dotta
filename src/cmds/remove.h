/**
 * remove.h - Remove paths from profiles or delete profiles
 *
 * Provides two main operations:
 * 1. Remove specific files/directories from a profile
 * 2. Delete an entire profile branch
 *
 * Architectural principle: this command modifies the Git repository and nothing
 * on disk; 'dotta apply' brings the filesystem in line.
 *
 * Removal is pure tree surgery — no content is captured, nothing needs a working
 * copy — so the Git phase is one draft, the profile's next commit (core/profiles.h
 * profile_draft_t): each claim removed by its own kind, the sheet pruned and
 * rewritten beside them, one commit; no per-file filesystem IO.
 */

#ifndef DOTTA_CMD_REMOVE_H
#define DOTTA_CMD_REMOVE_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Command options
 *
 * `profile` and `paths` are populated from the raw positional bucket by
 * `remove_post_parse`. Consumers read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_remove). */
    const char *profile;        /* Profile name (required) */
    char **paths;               /* Paths to remove (can be NULL for --delete-profile) */
    size_t path_count;          /* Number of paths */

    /* Operation modes */
    bool delete_profile;        /* Delete entire profile branch */
    bool delete_files;          /* The deployed paths deleted at the next apply */

    /* Safety flags */
    bool dry_run;               /* Show what would be removed without doing it */
    bool force;                 /* Skip confirmations */
    bool interactive;           /* Prompt for each path */

    /* Output flags */
    int verbosity;              /* dotta_verbosity_t (int for ARGS_FLAG_SET) */

    /* Git flags */
    const char *message;        /* Custom commit message (optional) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_remove_options_t;

/**
 * Remove files from a profile or delete a profile
 *
 * Behavior depends on options:
 * - If delete_profile=true: Deletes the entire profile branch
 * - If delete_profile=false: Removes specified files from profile
 *
 * This command modifies the Git repository and nothing on disk: the deployed
 * copies of what it removes are the next apply's to settle, decided with the
 * landings they may stand in the way of. With delete_files=true, this machine's
 * copies of the claims it removes are ordered pruned — those the next apply can
 * measure, and on a deletion those dotta created. The order is this machine's
 * own, a column of its record; another machine meets the commit at its next sync
 * and settles its own copies at its next apply.
 *
 * Executes hooks; never touches deployed files. Writes the record only for what
 * its commit knows: the reclaim of a claim it took whose node is gone, the orders,
 * a deletion's enabled row — non-fatal: Git stands even when the record write
 * fails, and the run says what the refusal loses that no later load re-derives,
 * the consent --delete-files gives.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_remove(const dotta_ctx_t *ctx, const cmd_remove_options_t *opts);

/**
 * Spec-engine command specification for `dotta remove`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in remove.c beside
 * the post_parse and dispatch wrappers.
 */
extern const args_command_t spec_remove;

#endif /* DOTTA_CMD_REMOVE_H */
