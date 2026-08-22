/**
 * apply.h - Apply profiles to filesystem
 *
 * Deploys files from profile branches to the filesystem.
 */

#ifndef DOTTA_CMD_APPLY_H
#define DOTTA_CMD_APPLY_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Command options
 */
typedef struct {
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    char **files;               /* Specific files to apply (NULL = all files) */
    size_t file_count;          /* Number of files */
    bool force;                 /* Override deploy's conflicts and cleanup's skip reasons */
    bool dry_run;               /* Don't actually deploy */
    bool keep_orphans;          /* Don't remove orphaned files (opt-out from default cleanup) */
    bool verbose;               /* Print verbose output */
    bool skip_existing;         /* Leave occupied paths alone (plan filter) */
    char **exclude_patterns;    /* Exclude patterns (glob) - read-only */
    size_t exclude_count;       /* Number of exclude patterns */
} cmd_apply_options_t;

/**
 * Apply profiles to filesystem
 *
 * Converges the filesystem with the enabled profiles in both directions: deploys
 * the files and tracked directories that diverge, and removes the ones orphaned
 * by a disabled profile or by a deletion in Git.
 *
 * Orchestrates scope resolution, workspace divergence analysis, plan construction,
 * privilege and pre-flight checks, the apply hooks, and execution. Builds no
 * manifest of its own — core/manifest maintains that when profiles or files change,
 * and apply reads it through the workspace.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_apply(const dotta_ctx_t *ctx, const cmd_apply_options_t *opts);

/**
 * Spec-engine command specification for `dotta apply`.
 *
 * Registered in cmds/registry.c. Defined in apply.c beside the dispatch wrapper.
 */
extern const args_command_t spec_apply;

#endif /* DOTTA_CMD_APPLY_H */
