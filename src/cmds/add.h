/**
 * add.h - Add files to profiles
 *
 * Adds files to git profile branches using temporary worktrees.
 */

#ifndef DOTTA_CMD_ADD_H
#define DOTTA_CMD_ADD_H

#include <git2.h>
#include <types.h>

#include "base/args.h"

/**
 * Encryption policy selector.
 *
 * Three user intentions: unset (let config policy decide), explicit
 * --encrypt (force on), explicit --no-encrypt (force off). Modelled
 * as a closed enum so the consumer can switch without bool-pair
 * reconciliation.
 */
typedef enum {
    ADD_ENCRYPT_DEFAULT = 0, /* No flag: config policy applies */
    ADD_ENCRYPT_FORCE_ON,    /* --encrypt:    force encryption */
    ADD_ENCRYPT_FORCE_OFF    /* --no-encrypt: force no encryption */
} add_encrypt_mode_t;

/**
 * Command options
 *
 * `profile` and `files` are populated from the raw positional bucket
 * by `add_post_parse`. Consumers read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_add). */
    const char *profile;        /* Profile name (required) */
    char **files;               /* Array of file paths (required) */
    size_t file_count;          /* Number of files */
    const char *custom_prefix;  /* Custom prefix (optional, for custom/ storage) */
    const char *message;        /* Commit message (optional) */
    char **exclude_patterns;    /* Exclude patterns (glob) - read-only */
    size_t exclude_count;       /* Number of exclude patterns */
    bool force;                 /* Overwrite existing files in profile */
    bool verbose;               /* Print verbose output */
    int encrypt_mode;           /* add_encrypt_mode_t (int for ARGS_FLAG_SET) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_add_options_t;

/**
 * Add files to a profile
 *
 * Uses temporary worktree to safely add files to a profile branch.
 * Creates the profile branch if it doesn't exist.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_add(const args_ctx_t *ctx, const cmd_add_options_t *opts);

/**
 * Spec-engine command specification for `dotta add`.
 *
 * Registered in cmds/registry.c. Defined in add.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_add;

#endif /* DOTTA_CMD_ADD_H */
