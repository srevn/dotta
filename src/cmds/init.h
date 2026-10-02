/**
 * init.h - Initialize dotta repository
 *
 * Creates a new dotta repository with initial branch structure.
 */

#ifndef DOTTA_CMD_INIT_H
#define DOTTA_CMD_INIT_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

#include "crypto/kdf.h"

/**
 * Command options
 */
typedef struct {
    const char *repo_path;        /* Repository path (NULL = the configured location) */
    const char *strength;         /* --strength's word (NULL = none given) */
    const kdf_preset_t *preset;   /* Its preset, or the default's (init_post_parse) */
    int verbosity;                /* dotta_verbosity_t (int for ARGS_FLAG_SET) */
} cmd_init_options_t;

/**
 * Initialize a dotta repository
 *
 * Creates or opens a git repository and sets up dotta branch structure. Creates
 * initial empty state file.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_init(const dotta_ctx_t *ctx, const cmd_init_options_t *opts);

/**
 * Spec-engine command specification for `dotta init`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in init.c beside
 * the dispatch wrapper.
 */
extern const args_command_t spec_init;

#endif /* DOTTA_CMD_INIT_H */
