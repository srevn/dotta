/**
 * clone.h - Clone dotta repository command
 */

#ifndef DOTTA_CMD_CLONE_H
#define DOTTA_CMD_CLONE_H

#include <runtime.h>
#include <types.h>

/**
 * Bootstrap behavior selector.
 *
 * The user has three intentions, not two: unset (ask), explicit yes
 * (--bootstrap), explicit no (--no-bootstrap). Representing these as
 * a single `int` field removes the legacy bool-pair reconciliation
 * and hands the consumer a closed enum to switch on.
 */
typedef enum {
    CLONE_BOOTSTRAP_DEFAULT = 0, /* No flag given: prompt if scripts exist */
    CLONE_BOOTSTRAP_FORCE,       /* --bootstrap:    auto-run */
    CLONE_BOOTSTRAP_SKIP         /* --no-bootstrap: never run */
} clone_bootstrap_mode_t;

/**
 * Clone options
 *
 * `url` and `path` are filled from the raw positional bucket by
 * `clone_post_parse`. Consumers read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_clone). */
    const char *url;          /* Remote URL (required) */
    const char *path;         /* Local path (NULL = auto-generate from URL) */
    bool quiet;               /* Suppress output */
    bool verbose;             /* Verbose output */
    int bootstrap_mode;       /* clone_bootstrap_mode_t (int for ARGS_FLAG_SET) */
    bool fetch_all;           /* Fetch all remote profiles (hub mode) */
    char **profiles;          /* Explicit profiles to fetch (NULL = auto-detect) */
    size_t profile_count;     /* Number of explicit profiles */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_clone_options_t;

/**
 * Clone dotta repository
 *
 * Clones remote repository and sets up dotta-worktree branch.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Clone options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_clone(const dotta_ctx_t *ctx, const cmd_clone_options_t *opts);

/**
 * Spec-engine command specification for `dotta clone`.
 *
 * Registered in cmds/registry.c. Defined in clone.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_clone;

#endif /* DOTTA_CMD_CLONE_H */
