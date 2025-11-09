/**
 * hooks.c - Hook execution system implementation
 */

#include "hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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
 *
 * Creates environment array with DOTTA_* variables and filtered system environment.
 * Caller must free with free_hook_env().
 *
 * Returns NULL on allocation failure, with env_count set to 0.
 */
static char **build_hook_env(const hook_context_t *context, size_t *env_count) {
    if (!context) {
        *env_count = 0;
        return NULL;
    }

    /* Initialize output */
    *env_count = 0;

    /* Sanity check: prevent excessive file counts from creating huge environments */
    if (context->file_count > 10000) {
        /* This is almost certainly a mistake - hooks don't need 10k+ files */
        return NULL;
    }

    /* Count environment variables we'll include */
    extern char **environ;
    size_t system_env_count = 0;
    for (char **e = environ; *e; e++) {
        /* Skip DOTTA_* variables to avoid conflicts */
        if (!str_starts_with(*e, "DOTTA_")) {
            system_env_count++;
        }
    }

    /*
     * Calculate total environment size:
     * - DOTTA_REPO_DIR (if set)
     * - DOTTA_COMMAND (if set)
     * - DOTTA_PROFILE (if set)
     * - DOTTA_DRY_RUN (always)
     * - DOTTA_FILE_COUNT (always)
     * - DOTTA_FILE_0, DOTTA_FILE_1, ... (indexed file variables)
     * - System environment variables
     * - NULL terminator
     */
    size_t needed = 3 + /* DOTTA_DRY_RUN, DOTTA_FILE_COUNT, NULL */
                    (context->repo_dir ? 1 : 0) +
                    (context->command ? 1 : 0) +
                    (context->profile ? 1 : 0) +
                    context->file_count + /* DOTTA_FILE_N indexed vars */
                    system_env_count;

    /* Allocate environment array */
    char **env = calloc(needed, sizeof(char *));
    if (!env) {
        return NULL;
    }

    size_t count = 0;

    /*
     * Add DOTTA_* variables
     * Use goto cleanup on allocation failure to free partial allocations
     */

    if (context->repo_dir) {
        env[count] = str_format("DOTTA_REPO_DIR=%s", context->repo_dir);
        if (!env[count]) {
            goto cleanup_failure;
        }
        count++;
    }

    if (context->command) {
        env[count] = str_format("DOTTA_COMMAND=%s", context->command);
        if (!env[count]) {
            goto cleanup_failure;
        }
        count++;
    }

    if (context->profile) {
        env[count] = str_format("DOTTA_PROFILE=%s", context->profile);
        if (!env[count]) {
            goto cleanup_failure;
        }
        count++;
    }

    env[count] = str_format("DOTTA_DRY_RUN=%s", context->dry_run ? "1" : "0");
    if (!env[count]) {
        goto cleanup_failure;
    }
    count++;

    env[count] = str_format("DOTTA_FILE_COUNT=%zu", context->file_count);
    if (!env[count]) {
        goto cleanup_failure;
    }
    count++;

    /* Add indexed file variables: DOTTA_FILE_0, DOTTA_FILE_1, ... */
    if (context->files && context->file_count > 0) {
        for (size_t i = 0; i < context->file_count; i++) {
            env[count] = str_format("DOTTA_FILE_%zu=%s", i, context->files[i]);
            if (!env[count]) {
                goto cleanup_failure;
            }
            count++;
        }
    }

    /* Copy system environment variables (PATH, HOME, etc.) */
    for (char **e = environ; *e; e++) {
        /* Skip DOTTA_* variables to avoid conflicts */
        if (!str_starts_with(*e, "DOTTA_")) {
            env[count] = strdup(*e);
            if (!env[count]) {
                goto cleanup_failure;
            }
            count++;
        }
    }

    /* NULL-terminate */
    env[count] = NULL;
    *env_count = count;

    return env;

cleanup_failure:
    /* Free all allocated strings on failure */
    for (size_t i = 0; i < count; i++) {
        free(env[i]);
    }
    free(env);
    *env_count = 0;
    return NULL;
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
 * Simple SIGALRM handler for hook timeout
 * Just needs to interrupt waitpid() - no action required
 */
static void hook_timeout_handler(int sig) {
    (void)sig;  /* Unused */
    /* Handler does nothing - just interrupts waitpid() */
}

/**
 * Execute hook script with timeout and comprehensive error handling
 *
 * Resource management:
 * - All resources initialized to safe values
 * - Single cleanup label ensures proper cleanup on all error paths
 * - Child process properly reaped even on timeout/error
 *
 * Timeout behavior:
 * - Uses alarm() + SIGALRM to interrupt waitpid()
 * - On timeout: sends SIGTERM, waits 5s, then SIGKILL if needed
 * - Restores previous alarm and signal handler state
 *
 * Returns NULL on success or if hook is disabled/missing.
 * Returns error if hook fails or times out.
 */
error_t *hook_execute(
    const dotta_config_t *config,
    hook_type_t type,
    const hook_context_t *context,
    hook_result_t **result
) {
    CHECK_NULL(config);
    CHECK_NULL(context);

    /* Initialize result if requested */
    if (result) {
        *result = NULL;
    }

    /* Early check: hook enabled? */
    if (!hook_is_enabled(config, type)) {
        return NULL;  /* Disabled - skip silently */
    }

    /*
     * Initialize all resources to safe values
     * This allows cleanup label to safely free/close everything
     */
    char *hook_path = NULL;
    char **env = NULL;
    size_t env_count = 0;
    int pipefd[2] = {-1, -1};
    char *output = NULL;
    size_t output_size = 0;
    size_t output_capacity = 0;
    pid_t pid = -1;
    hook_result_t *res = NULL;
    error_t *err = NULL;
    struct sigaction sa_old, sa_new;
    bool sigaction_installed = false;

    /* Get hook script path */
    err = hook_get_path(config, type, &hook_path);
    if (err) {
        goto cleanup;
    }

    /* Check if hook script exists */
    if (!fs_file_exists(hook_path)) {
        /* Not an error - just doesn't exist */
        goto cleanup;
    }

    /* Check if hook is executable */
    if (!fs_is_executable(hook_path)) {
        err = ERROR(ERR_PERMISSION,
                   "Hook '%s' is not executable", hook_type_name(type));
        goto cleanup;
    }

    /* Build environment for hook */
    env = build_hook_env(context, &env_count);
    if (!env) {
        err = ERROR(ERR_MEMORY, "Failed to build environment for hook");
        goto cleanup;
    }

    /* Create pipe for capturing hook output */
    if (pipe(pipefd) == -1) {
        err = ERROR(ERR_FS, "Failed to create pipe for hook output: %s",
                   strerror(errno));
        goto cleanup;
    }

    /* Set close-on-exec flags for security */
    (void)fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    /* Fork to execute hook */
    pid = fork();
    if (pid == -1) {
        err = ERROR(ERR_FS, "Failed to fork for hook execution: %s",
                   strerror(errno));
        goto cleanup;
    }

    if (pid == 0) {
        /*
         * Child process
         * No cleanup needed here - execve replaces process
         * If execve fails, _exit() terminates without cleanup
         *
         * Exit codes:
         *   126 - Child setup failed (dup2, etc.)
         *   127 - execve failed (hook not found, not executable, etc.)
         */

        /* Cancel any inherited alarms */
        alarm(0);

        /* Redirect stdin to /dev/null to prevent hook from reading terminal */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            if (dup2(devnull, STDIN_FILENO) == -1) {
                /* stdin redirect failed - non-fatal, continue */
                const char *msg = "dotta: warning: failed to redirect stdin\n";
                (void)write(STDERR_FILENO, msg, strlen(msg));
            }
            close(devnull);
        }

        close(pipefd[0]);  /* Close read end */

        /* Redirect stdout and stderr to pipe - critical for capturing hook output */
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            const char *msg = "dotta: error: failed to redirect stdout\n";
            (void)write(STDERR_FILENO, msg, strlen(msg));
            close(pipefd[1]);
            _exit(126);
        }
        if (dup2(pipefd[1], STDERR_FILENO) == -1) {
            /* stdout already redirected, write error there so parent captures it */
            const char *msg = "dotta: error: failed to redirect stderr\n";
            (void)write(STDOUT_FILENO, msg, strlen(msg));
            close(pipefd[1]);
            _exit(126);
        }
        close(pipefd[1]);

        /* Execute hook with environment */
        char *args[] = { hook_path, NULL };
        execve(hook_path, args, env);

        /* If execve returns, it failed */
        perror("execve");
        _exit(127);
    }

    /*
     * Parent process continues
     */

    /* Close write end of pipe (child owns it now) */
    close(pipefd[1]);
    pipefd[1] = -1;

    /*
     * The timeout must cover both the read phase (child generating output)
     * and the wait phase (child doing work after closing output)
     */
    if (config->hook_timeout > 0) {
        /* Install signal handler for timeout */
        memset(&sa_new, 0, sizeof(sa_new));
        sa_new.sa_handler = hook_timeout_handler;
        sigemptyset(&sa_new.sa_mask);
        sa_new.sa_flags = 0;  /* No SA_RESTART - we want EINTR */

        if (sigaction(SIGALRM, &sa_new, &sa_old) == 0) {
            sigaction_installed = true;
        }

        /* Start timeout countdown NOW (before reading) */
        alarm((unsigned int)config->hook_timeout);
    }

    /* Allocate buffer for reading hook output */
    output_capacity = 4096;
    output = malloc(output_capacity);
    if (!output) {
        err = ERROR(ERR_MEMORY, "Failed to allocate buffer for hook output");
        goto cleanup;
    }

    /*
     * Read output from pipe
     * This may be interrupted by SIGALRM if hook times out during output
     */
    ssize_t n;
    char buf[1024];
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        /* Expand buffer if needed */
        if (output_size + (size_t)n + 1 > output_capacity) {
            output_capacity *= 2;
            char *new_output = realloc(output, output_capacity);
            if (!new_output) {
                err = ERROR(ERR_MEMORY, "Failed to resize hook output buffer");
                goto cleanup;
            }
            output = new_output;
        }
        memcpy(output + output_size, buf, (size_t)n);
        output_size += (size_t)n;
    }

    /*
     * Check why read loop exited
     * - n == 0: EOF (child closed its output normally)
     * - n == -1 && errno == EINTR: Timeout during read
     * - n == -1 && errno != EINTR: Read error
     */
    bool timed_out = false;
    if (n == -1) {
        if (errno == EINTR) {
            /* Timeout occurred during read phase */
            timed_out = true;
        } else {
            /* Real I/O error */
            err = ERROR(ERR_FS, "Failed to read hook output: %s", strerror(errno));
            goto cleanup;
        }
    }

    /* Close read end of pipe */
    close(pipefd[0]);
    pipefd[0] = -1;

    /* Null-terminate output */
    output[output_size] = '\0';

    /*
     * Handle timeout or wait for child to complete
     */
    int status = 0;

    if (timed_out) {
        /*
         * Hook timed out during read phase
         * Kill child and reap it
         */
        kill(pid, SIGTERM);

        /* Give it 5 seconds to exit gracefully */
        alarm(5);
        if (waitpid(pid, &status, 0) == -1) {
            /* Still won't die - use SIGKILL */
            kill(pid, SIGKILL);
            alarm(0);
            waitpid(pid, &status, 0);  /* Must reap zombie */
        }
        alarm(0);

        pid = -1;  /* Process reaped */
        err = ERROR(ERR_INTERNAL,
                   "Hook '%s' exceeded timeout of %d seconds",
                   hook_type_name(type), config->hook_timeout);
        goto cleanup;
    }

    /*
     * Read completed normally (no timeout yet)
     * Now wait for child to exit (alarm still active if configured)
     */
    if (config->hook_timeout > 0) {
        /* Alarm is still counting - wait may be interrupted */
        if (waitpid(pid, &status, 0) == -1) {
            if (errno == EINTR) {
                /* Timeout occurred during wait phase */
                kill(pid, SIGTERM);

                alarm(5);
                if (waitpid(pid, &status, 0) == -1) {
                    kill(pid, SIGKILL);
                    alarm(0);
                    waitpid(pid, &status, 0);
                }
                alarm(0);

                pid = -1;
                err = ERROR(ERR_INTERNAL,
                           "Hook '%s' exceeded timeout of %d seconds",
                           hook_type_name(type), config->hook_timeout);
                goto cleanup;
            } else {
                /* Other error */
                err = ERROR(ERR_FS, "Failed to wait for hook process: %s",
                           strerror(errno));
                goto cleanup;
            }
        }

        /* Success - fall through to cleanup which will restore signal handler */
    } else {
        /* No timeout configured - simple wait */
        if (waitpid(pid, &status, 0) == -1) {
            err = ERROR(ERR_FS, "Failed to wait for hook process: %s",
                       strerror(errno));
            goto cleanup;
        }
    }

    pid = -1;  /* Process reaped */


    /* Check exit status */
    int exit_code;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    } else {
        exit_code = 1;
    }

    /* Create result structure if requested */
    if (result) {
        res = calloc(1, sizeof(hook_result_t));
        if (res) {
            res->exit_code = exit_code;
            res->output = output;
            res->aborted = (exit_code != 0);
            *result = res;
            output = NULL;  /* Ownership transferred to result */
        } else {
            err = ERROR(ERR_MEMORY, "Failed to allocate hook result");
            goto cleanup;
        }
    }

    /* Return error if hook failed */
    if (exit_code != 0) {
        if (exit_code == 126) {
            err = ERROR(ERR_INTERNAL,
                       "Hook '%s' failed: child process setup error (exit code %d)",
                       hook_type_name(type), exit_code);
        } else if (exit_code == 127) {
            err = ERROR(ERR_INTERNAL,
                       "Hook '%s' failed: command not found or not executable (exit code %d)",
                       hook_type_name(type), exit_code);
        } else {
            err = ERROR(ERR_INTERNAL,
                       "Hook '%s' failed with exit code %d",
                       hook_type_name(type), exit_code);
        }
        goto cleanup;
    }

cleanup:
    /*
     * Cleanup all resources in reverse order of acquisition
     * Safe to call even if resource was never allocated (initialized to safe values)
     */

    /* Cancel alarm and restore signal handler (if timeout was configured) */
    if (config->hook_timeout > 0) {
        alarm(0);
        if (sigaction_installed) {
            sigaction(SIGALRM, &sa_old, NULL);
        }
    }

    /* Close any open file descriptors */
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);

    /* Reap child if still running (shouldn't happen, but be defensive) */
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    /* Free memory */
    if (env) {
        free_hook_env(env, env_count);
    }
    free(hook_path);

    /* Free output only if not transferred to result */
    if (output && !res) {
        free(output);
    }

    /* Set result even on error (caller can see output) */
    if (result && res) {
        *result = res;
    } else if (res) {
        /* Result created but caller doesn't want it */
        hook_result_free(res);
    }

    return err;
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
