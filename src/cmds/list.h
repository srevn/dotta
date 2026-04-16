/**
 * list.h - List profiles, files, and history
 *
 * Hierarchical listing interface:
 * - Level 1: Profiles (default)
 * - Level 2: Files (with -p flag)
 * - Level 3: File history (with -p flag + file path)
 *
 * The --verbose flag adds detail at each level.
 */

#ifndef DOTTA_CMD_LIST_H
#define DOTTA_CMD_LIST_H

#include <git2.h>
#include <types.h>

#include "base/args.h"

/**
 * List mode (determined by arguments)
 */
typedef enum {
    LIST_PROFILES,           /* List all profiles */
    LIST_FILES,              /* List files in profile */
    LIST_FILE_HISTORY        /* Show history of specific file */
} list_mode_t;

/**
 * Command options
 *
 * `mode`, `profile`, and `file_path` are derived by `list_post_parse`
 * from the raw positional bucket. Consumers read only the user-facing
 * fields.
 */
typedef struct {
    /* User-facing (read by cmd_list). */
    list_mode_t mode;        /* What to list (auto-determined) */
    const char *profile;     /* Profile name (for LIST_FILES or LIST_FILE_HISTORY) */
    const char *file_path;   /* File path (for LIST_FILE_HISTORY) */
    bool verbose;            /* Print detailed output */
    bool remote;             /* Show remote tracking state */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_list_options_t;

/**
 * List profiles or files
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_list(const args_ctx_t *ctx, const cmd_list_options_t *opts);

/**
 * Spec-engine command specification for `dotta list`.
 *
 * Registered in cmds/registry.c. Defined in list.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_list;

#endif /* DOTTA_CMD_LIST_H */
