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
 *
 * `skip_unchanged` is an int (not bool) because the spec engine's
 * `ARGS_FLAG_SET` writes int-sized values. `--no-skip-unchanged` sets
 * it to 0; `init_defaults` seeds it to 1. Consumers test truthiness,
 * which works transparently for both int and bool.
 */
typedef struct {
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    char **files;               /* Specific files to apply (NULL = all files) */
    size_t file_count;          /* Number of files */
    bool force;                 /* Overwrite modified files */
    bool dry_run;               /* Don't actually deploy */
    bool keep_orphans;          /* Don't remove orphaned files (opt-out from default cleanup) */
    bool verbose;               /* Print verbose output */
    bool skip_existing;         /* Skip files that already exist */
    int skip_unchanged;         /* Skip files matching profile content (default: 1) */
    char **exclude_patterns;    /* Exclude patterns (glob) - read-only */
    size_t exclude_count;       /* Number of exclude patterns */
} cmd_apply_options_t;

/**
 * Apply profiles to filesystem
 *
 * Orchestrates profile detection/loading, manifest building,
 * pre-flight checks, and deployment.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_apply(const dotta_ctx_t *ctx, const cmd_apply_options_t *opts);

/**
 * Spec-engine command specification for `dotta apply`.
 *
 * Registered in cmds/registry.c. Defined in apply.c beside the
 * dispatch wrapper.
 */
extern const args_command_t spec_apply;

#endif /* DOTTA_CMD_APPLY_H */
