/**
 * hooks.h - Hook execution system
 *
 * Provides pre/post command hooks for extensibility.
 * Hooks are shell scripts that run before or after commands.
 */

#ifndef DOTTA_HOOKS_H
#define DOTTA_HOOKS_H

#include <stdbool.h>

#include "config.h"
#include "dotta/types.h"

/**
 * Hook types
 */
typedef enum {
    HOOK_PRE_ADD,
    HOOK_POST_ADD,
    HOOK_PRE_REMOVE,
    HOOK_POST_REMOVE,
    HOOK_PRE_APPLY,
    HOOK_POST_APPLY,
    HOOK_PRE_CLEAN,
    HOOK_POST_CLEAN
} hook_type_t;

/**
 * Hook context - information passed to hooks
 */
typedef struct {
    const char *repo_dir;        /* Repository directory */
    const char *command;         /* Command being executed */
    const char *profile;         /* Profile name (if applicable) */
    const char **files;          /* Array of file paths (if applicable) */
    size_t file_count;           /* Number of files */
    bool dry_run;                /* Is this a dry-run? */
} hook_context_t;

/**
 * Hook result
 */
typedef struct {
    int exit_code;               /* Exit code from hook script */
    char *output;                /* Captured stdout/stderr */
    bool aborted;                /* Whether hook aborted the operation */
} hook_result_t;

/**
 * Check if a hook is enabled in config
 */
bool hook_is_enabled(const dotta_config_t *config, hook_type_t type);

/**
 * Check if hook script exists
 */
bool hook_exists(const dotta_config_t *config, hook_type_t type);

/**
 * Get hook script path
 */
dotta_error_t *hook_get_path(
    const dotta_config_t *config,
    hook_type_t type,
    char **out
);

/**
 * Execute hook
 *
 * Returns NULL if hook succeeds or doesn't exist.
 * Returns error if hook fails with non-zero exit code.
 *
 * @param config Configuration (contains hooks_dir and enabled flags)
 * @param type Hook type to execute
 * @param context Hook context (command, files, etc.)
 * @param result Optional result struct (can be NULL)
 * @return Error or NULL on success
 */
dotta_error_t *hook_execute(
    const dotta_config_t *config,
    hook_type_t type,
    const hook_context_t *context,
    hook_result_t **result
);

/**
 * Free hook result
 */
void hook_result_free(hook_result_t *result);

/**
 * Get hook name as string
 */
const char *hook_type_name(hook_type_t type);

/**
 * Helper: Create hook context
 */
hook_context_t *hook_context_create(
    const char *repo_dir,
    const char *command,
    const char *profile
);

/**
 * Helper: Add files to hook context
 */
dotta_error_t *hook_context_add_files(
    hook_context_t *ctx,
    const char **files,
    size_t count
);

/**
 * Free hook context
 */
void hook_context_free(hook_context_t *ctx);

#endif /* DOTTA_HOOKS_H */
