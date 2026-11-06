/**
 * list.h - List profiles, files, and history
 *
 * Hierarchical listing interface:
 * - Level 1: Profiles (default)
 * - Level 2: Files (with -p flag)
 * - Level 3: A path's history (with -p flag + path) — a file's, or a directory's
 *   whichever of the profile's two documents holds it: every commit that changed
 *   anything beneath it; a submodule is refused as one, and a name neither holds
 *   is searched for through the history
 *
 * The --verbose flag adds detail at each level.
 */

#ifndef DOTTA_CMD_LIST_H
#define DOTTA_CMD_LIST_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * List mode (determined by arguments)
 */
typedef enum {
    LIST_PROFILES,           /* List all profiles */
    LIST_FILES,              /* List files in profile */
    LIST_PATH_HISTORY        /* Show history of a path: a file or a directory */
} list_mode_t;

/**
 * Command options
 *
 * `mode`, `profile`, and `path` are derived by `list_post_parse` from the raw
 * positional bucket. Consumers read only the user-facing fields.
 */
typedef struct {
    /* User-facing (read by cmd_list). */
    list_mode_t mode;        /* What to list (auto-determined) */
    const char *profile;     /* Profile name (for LIST_FILES or LIST_PATH_HISTORY) */
    const char *path;        /* The path whose history is listed (for LIST_PATH_HISTORY) */
    int verbosity;           /* dotta_verbosity_t (int for ARGS_FLAG_SET) */
    bool remote;             /* Show remote sync status */

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
error_t cmd_list(const dotta_ctx_t *ctx, const cmd_list_options_t *opts);

/**
 * Spec-engine command specification for `dotta list`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in list.c beside
 * the post_parse and dispatch wrappers.
 */
extern const args_command_t spec_list;

#endif /* DOTTA_CMD_LIST_H */
