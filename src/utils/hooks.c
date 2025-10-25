/**
 * hooks.c - Hook execution system implementation
 */

#include "hooks.h"

#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "infra/path.h"
#include "string.h"

/* Hook script names */
static const char *HOOK_NAMES[] = {
    [HOOK_PRE_ADD]     = "pre-add",
    [HOOK_POST_ADD]    = "post-add",
    [HOOK_PRE_REMOVE]  = "pre-remove",
    [HOOK_POST_REMOVE] = "post-remove",
    [HOOK_PRE_APPLY]   = "pre-apply",
    [HOOK_POST_APPLY]  = "post-apply",
    [HOOK_PRE_UPDATE]  = "pre-update",
    [HOOK_POST_UPDATE] = "post-update"
};

/**
 * Get hook name as string
 */
const char *hook_type_name(hook_type_t type) {
    if (type >= 0 && type < (sizeof(HOOK_NAMES) / sizeof(HOOK_NAMES[0]))) {
        return HOOK_NAMES[type];
    }
    return "unknown";
}

/**
 * Check if a hook is enabled in config
 */
bool hook_is_enabled(const dotta_config_t *config, hook_type_t type) {
    if (!config) {
        return false;
    }

    switch (type) {
    case HOOK_PRE_ADD:
        return config->pre_add;
    case HOOK_POST_ADD:
        return config->post_add;
    case HOOK_PRE_REMOVE:
        return config->pre_remove;
    case HOOK_POST_REMOVE:
        return config->post_remove;
    case HOOK_PRE_APPLY:
        return config->pre_apply;
    case HOOK_POST_APPLY:
        return config->post_apply;
    case HOOK_PRE_UPDATE:
        return config->pre_update;
    case HOOK_POST_UPDATE:
        return config->post_update;
    default:
        return false;
    }
}

/**
 * Get hook script path
 */
error_t *hook_get_path(
    const dotta_config_t *config,
    hook_type_t type,
    char **out
) {
    CHECK_NULL(config);
    CHECK_NULL(out);

    const char *hook_name = hook_type_name(type);
    if (!hook_name || strcmp(hook_name, "unknown") == 0) {
        return ERROR(ERR_INVALID_ARG, "Invalid hook type: %d", type);
    }

    /* Get hooks directory */
    char *hooks_dir = NULL;
    error_t *err = NULL;

    if (config->hooks_dir) {
        err = path_expand_home(config->hooks_dir, &hooks_dir);
    } else {
        /* Use default */
        err = path_expand_home("~/.config/dotta/hooks", &hooks_dir);
    }

    if (err) {
        return error_wrap(err, "Failed to resolve hooks directory");
    }

    /* Build hook script path */
    err = fs_path_join(hooks_dir, hook_name, out);
    free(hooks_dir);

    return err;
}

/**
 * Check if hook script exists
 */
bool hook_exists(const dotta_config_t *config, hook_type_t type) {
    char *hook_path = NULL;

    error_t *err = hook_get_path(config, type, &hook_path);
    if (err) {
        error_free(err);
        return false;
    }

    bool exists = fs_file_exists(hook_path);
    free(hook_path);

    return exists;
}

/**
 * Build environment variables for hook
 */
static char **build_hook_env(const hook_context_t *context, size_t *env_count) {
    if (!context) {
        *env_count = 0;
        return NULL;
    }

    /* Count environment variables */
    size_t count = 0;
    char **env = malloc(32 * sizeof(char *));
    if (!env) {
        *env_count = 0;
        return NULL;
    }

    /* Add DOTTA_REPO_DIR */
    if (context->repo_dir) {
        env[count++] = str_format("DOTTA_REPO_DIR=%s", context->repo_dir);
    }

    /* Add DOTTA_COMMAND */
    if (context->command) {
        env[count++] = str_format("DOTTA_COMMAND=%s", context->command);
    }

    /* Add DOTTA_PROFILE */
    if (context->profile) {
        env[count++] = str_format("DOTTA_PROFILE=%s", context->profile);
    }

    /* Add DOTTA_DRY_RUN */
    env[count++] = str_format("DOTTA_DRY_RUN=%s", context->dry_run ? "1" : "0");

    /* Add DOTTA_FILE_COUNT */
    env[count++] = str_format("DOTTA_FILE_COUNT=%zu", context->file_count);

    /* Add DOTTA_FILES (space-separated) */
    if (context->files && context->file_count > 0) {
        /* Calculate total length */
        size_t total_len = 0;
        for (size_t i = 0; i < context->file_count; i++) {
            total_len += strlen(context->files[i]) + 1; /* +1 for space/null */
        }

        char *files_str = malloc(total_len + 16); /* +16 for "DOTTA_FILES=" */
        if (files_str) {
            strcpy(files_str, "DOTTA_FILES=");
            char *p = files_str + strlen(files_str);

            for (size_t i = 0; i < context->file_count; i++) {
                if (i > 0) {
                    *p++ = ' ';
                }
                strcpy(p, context->files[i]);
                p += strlen(context->files[i]);
            }

            env[count++] = files_str;
        }
    }

    /* Copy existing environment variables (PATH, HOME, etc.) */
    extern char **environ;
    for (char **e = environ; *e && count < 30; e++) {
        /* Skip DOTTA_* variables to avoid conflicts */
        if (!str_starts_with(*e, "DOTTA_")) {
            env[count++] = strdup(*e);
        }
    }

    /* NULL-terminate */
    env[count] = NULL;
    *env_count = count;

    return env;
}

/**
 * Free environment array
 */
static void free_hook_env(char **env, size_t count) {
    if (!env) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(env[i]);
    }
    free(env);
}

/**
 * Execute hook script
 */
error_t *hook_execute(
    const dotta_config_t *config,
    hook_type_t type,
    const hook_context_t *context,
    hook_result_t **result
) {
    CHECK_NULL(config);
    CHECK_NULL(context);

    /* Check if hook is enabled */
    if (!hook_is_enabled(config, type)) {
        /* Hook disabled, skip silently */
        if (result) {
            *result = NULL;
        }
        return NULL;
    }

    /* Check if hook script exists */
    char *hook_path = NULL;
    error_t *err = hook_get_path(config, type, &hook_path);
    if (err) {
        return err;
    }

    if (!fs_file_exists(hook_path)) {
        /* Hook script doesn't exist, skip silently */
        free(hook_path);
        if (result) {
            *result = NULL;
        }
        return NULL;
    }

    /* Check if hook is executable */
    if (!fs_is_executable(hook_path)) {
        free(hook_path);
        return ERROR(ERR_PERMISSION,
                    "Hook '%s' is not executable", hook_type_name(type));
    }

    /* Build environment */
    size_t env_count = 0;
    char **env = build_hook_env(context, &env_count);

    /* Create pipes for capturing output */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        free_hook_env(env, env_count);
        free(hook_path);
        return ERROR(ERR_FS, "Failed to create pipe for hook output");
    }

    /* Fork and execute hook */
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        free_hook_env(env, env_count);
        free(hook_path);
        return ERROR(ERR_FS, "Failed to fork for hook execution");
    }

    if (pid == 0) {
        /* Child process */
        close(pipefd[0]); /* Close read end */

        /* Redirect stdout and stderr to pipe */
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Execute hook with environment */
        char *args[] = { hook_path, NULL };
        execve(hook_path, args, env);

        /* If execve returns, it failed */
        _exit(127);
    }

    /* Parent process */
    close(pipefd[1]); /* Close write end */

    /* Read output from pipe */
    char *output = NULL;
    size_t output_size = 0;
    size_t output_capacity = 4096;
    output = malloc(output_capacity);
    if (!output) {
        close(pipefd[0]);
        free_hook_env(env, env_count);
        free(hook_path);
        return ERROR(ERR_MEMORY, "Failed to allocate buffer for hook output");
    }

    ssize_t n;
    char buf[1024];
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        if (output_size + (size_t)n >= output_capacity) {
            output_capacity *= 2;
            char *new_output = realloc(output, output_capacity);
            if (!new_output) {
                free(output);
                close(pipefd[0]);
                free_hook_env(env, env_count);
                free(hook_path);
                return ERROR(ERR_MEMORY, "Failed to resize hook output buffer");
            }
            output = new_output;
        }
        memcpy(output + output_size, buf, (size_t)n);
        output_size += (size_t)n;
    }
    close(pipefd[0]);

    /* Null-terminate output */
    if (output_size < output_capacity) {
        output[output_size] = '\0';
    } else {
        char *new_output = realloc(output, output_size + 1);
        if (new_output) {
            output = new_output;
            output[output_size] = '\0';
        }
    }

    /* Wait for child process */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        free(output);
        free_hook_env(env, env_count);
        free(hook_path);
        return ERROR(ERR_FS, "Failed to wait for hook process");
    }

    /* Check exit status */
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    /* Create result if requested */
    if (result) {
        hook_result_t *res = calloc(1, sizeof(hook_result_t));
        if (res) {
            res->exit_code = exit_code;
            res->output = output;
            res->aborted = (exit_code != 0);
            *result = res;
        } else {
            free(output);
        }
    } else {
        free(output);
    }

    /* Cleanup */
    free_hook_env(env, env_count);
    free(hook_path);

    /* Return error if hook failed */
    if (exit_code != 0) {
        return ERROR(ERR_INTERNAL,
                    "Hook '%s' failed with exit code %d",
                    hook_type_name(type), exit_code);
    }

    return NULL;
}

/**
 * Free hook result
 */
void hook_result_free(hook_result_t *result) {
    if (!result) {
        return;
    }

    free(result->output);
    free(result);
}

/**
 * Helper: Create hook context
 */
hook_context_t *hook_context_create(
    const char *repo_dir,
    const char *command,
    const char *profile
) {
    hook_context_t *ctx = calloc(1, sizeof(hook_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->repo_dir = repo_dir;
    ctx->command = command;
    ctx->profile = profile;
    ctx->files = NULL;
    ctx->file_count = 0;
    ctx->dry_run = false;

    return ctx;
}

/**
 * Helper: Add files to hook context
 */
error_t *hook_context_add_files(
    hook_context_t *ctx,
    char **files,
    size_t count
) {
    CHECK_NULL(ctx);

    if (!files || count == 0) {
        return NULL;
    }

    ctx->files = files;
    ctx->file_count = count;

    return NULL;
}

/**
 * Free hook context
 */
void hook_context_free(hook_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Note: We don't free the strings themselves as they're not owned by the context */
    free(ctx);
}
