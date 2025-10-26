/**
 * bootstrap.c - Bootstrap script execution system implementation
 */

#include "bootstrap.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "utils/string.h"

/**
 * Check if bootstrap script exists for profile
 */
bool bootstrap_exists(
    git_repository *repo,
    const char *profile_name,
    const char *script_name
) {
    if (!repo || !profile_name) {
        return false;
    }

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Check if profile branch exists */
    bool exists = false;
    error_t *err = gitops_branch_exists(repo, profile_name, &exists);
    if (err || !exists) {
        if (err) error_free(err);
        return false;
    }

    /* Build ref name */
    char *ref_name = str_format("refs/heads/%s", profile_name);
    if (!ref_name) {
        return false;
    }

    /* Load tree from profile branch */
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, ref_name, &tree);
    free(ref_name);

    if (err) {
        error_free(err);
        return false;
    }

    /* Look for .bootstrap file directly in root */
    const git_tree_entry *bootstrap_entry = git_tree_entry_byname(tree, script_name);
    bool found = (bootstrap_entry != NULL);

    git_tree_free(tree);

    return found;
}

/**
 * Get path to bootstrap script for a profile
 */
error_t *bootstrap_get_path(
    const char *repo_dir,
    const char *profile_name,
    const char *script_name,
    char **out
) {
    CHECK_NULL(repo_dir);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Build path: <repo_dir>/<profile>/<script_name> */
    char *profile_path = NULL;
    error_t *err = fs_path_join(repo_dir, profile_name, &profile_path);
    if (err) {
        return error_wrap(err, "Failed to build profile path");
    }

    char *script_path = NULL;
    err = fs_path_join(profile_path, script_name, &script_path);
    free(profile_path);
    if (err) {
        return error_wrap(err, "Failed to build bootstrap script path");
    }

    *out = script_path;
    return NULL;
}

/**
 * Build environment for bootstrap script
 */
static char **build_bootstrap_env(const bootstrap_context_t *context, size_t *env_count) {
    if (!context) {
        *env_count = 0;
        return NULL;
    }

    /* Count how many environment variables we need */
    extern char **environ;
    size_t env_var_count = 0;
    for (char **e = environ; *e; e++) {
        /* Skip DOTTA_* variables as we'll add our own */
        if (!str_starts_with(*e, "DOTTA_")) {
            env_var_count++;
        }
    }

    /* Calculate total capacity: 4 DOTTA_* vars + existing vars + NULL terminator */
    size_t capacity = 4 + env_var_count + 1;

    /* Allocate environment array dynamically based on actual need */
    char **env = malloc(capacity * sizeof(char *));
    if (!env) {
        *env_count = 0;
        return NULL;
    }

    size_t count = 0;

    /* Add DOTTA_REPO_DIR */
    if (context->repo_dir) {
        env[count] = str_format("DOTTA_REPO_DIR=%s", context->repo_dir);
        if (!env[count]) {
            goto cleanup_error;
        }
        count++;
    }

    /* Add DOTTA_PROFILE */
    if (context->profile_name) {
        env[count] = str_format("DOTTA_PROFILE=%s", context->profile_name);
        if (!env[count]) {
            goto cleanup_error;
        }
        count++;
    }

    /* Add DOTTA_PROFILES */
    if (context->all_profiles) {
        env[count] = str_format("DOTTA_PROFILES=%s", context->all_profiles);
        if (!env[count]) {
            goto cleanup_error;
        }
        count++;
    }

    /* Add DOTTA_DRY_RUN */
    env[count] = str_format("DOTTA_DRY_RUN=%s", context->dry_run ? "1" : "0");
    if (!env[count]) {
        goto cleanup_error;
    }
    count++;

    /* Copy existing environment variables (PATH, HOME, etc.) */
    for (char **e = environ; *e; e++) {
        /* Skip DOTTA_* variables to avoid conflicts */
        if (!str_starts_with(*e, "DOTTA_")) {
            env[count] = strdup(*e);
            if (!env[count]) {
                goto cleanup_error;
            }
            count++;
        }
    }

    /* NULL-terminate */
    env[count] = NULL;
    *env_count = count;

    return env;

cleanup_error:
    /* Free all allocated strings on error */
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
static void free_bootstrap_env(char **env, size_t count) {
    if (!env) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(env[i]);
    }
    free(env);
}

/**
 * Execute bootstrap script with environment
 */
error_t *bootstrap_execute(
    const char *script_path,
    const bootstrap_context_t *context,
    bootstrap_result_t **result
) {
    CHECK_NULL(script_path);
    CHECK_NULL(context);

    /* Check if script exists */
    if (!fs_file_exists(script_path)) {
        return ERROR(ERR_NOT_FOUND, "Bootstrap script not found: %s", script_path);
    }

    /* Check if script is executable */
    if (!fs_is_executable(script_path)) {
        return ERROR(ERR_PERMISSION,
                    "Bootstrap script is not executable: %s", script_path);
    }

    /* Validate shebang */
    FILE *fp = fopen(script_path, "r");
    if (!fp) {
        return ERROR(ERR_FS, "Failed to open bootstrap script for validation: %s", script_path);
    }

    char shebang[3] = {0};
    size_t read_bytes = fread(shebang, 1, 2, fp);
    fclose(fp);

    if (read_bytes < 2 || shebang[0] != '#' || shebang[1] != '!') {
        return ERROR(ERR_INVALID_ARG,
                    "Bootstrap script must start with shebang (#!): %s", script_path);
    }

    /* Build environment */
    size_t env_count = 0;
    char **env = build_bootstrap_env(context, &env_count);
    if (!env) {
        return ERROR(ERR_MEMORY, "Failed to build environment for bootstrap script");
    }

    /* Create pipes for capturing output */
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        free_bootstrap_env(env, env_count);
        return ERROR(ERR_FS, "Failed to create pipe for bootstrap output");
    }

    /* Get working directory (profile directory) */
    char *work_dir = NULL;
    if (context->repo_dir && context->profile_name) {
        error_t *err = fs_path_join(context->repo_dir, context->profile_name, &work_dir);
        if (err) {
            close(pipefd[0]);
            close(pipefd[1]);
            free_bootstrap_env(env, env_count);
            return error_wrap(err, "Failed to build working directory");
        }
    }

    /* Fork and execute bootstrap */
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        free_bootstrap_env(env, env_count);
        free(work_dir);
        return ERROR(ERR_FS, "Failed to fork for bootstrap execution");
    }

    if (pid == 0) {
        /* Child process */
        close(pipefd[0]); /* Close read end */

        /* Redirect stdout and stderr to pipe */
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Change to working directory if specified */
        if (work_dir) {
            if (chdir(work_dir) != 0) {
                fprintf(stderr, "Error: Failed to change to directory '%s': %s\n",
                        work_dir, strerror(errno));
                _exit(126);  /* Exit with error code 126 (cannot execute) */
            }
        }

        /* Execute bootstrap with environment */
        char *args[] = { (char *)script_path, NULL };
        execve(script_path, args, env);

        /* If execve returns, it failed */
        _exit(127);
    }

    /* Parent process */
    close(pipefd[1]); /* Close write end */
    free(work_dir);

    /* Read output from pipe */
    char *output = NULL;
    size_t output_size = 0;
    size_t output_capacity = 4096;
    output = malloc(output_capacity);
    if (!output) {
        close(pipefd[0]);
        free_bootstrap_env(env, env_count);
        return ERROR(ERR_MEMORY, "Failed to allocate buffer for bootstrap output");
    }

    ssize_t n;
    char buf[1024];
    while (1) {
        /* Read from pipe with EINTR handling */
        n = read(pipefd[0], buf, sizeof(buf));
        if (n < 0) {
            /* Retry on signal interruption */
            if (errno == EINTR) {
                continue;
            }
            /* Real error - stop reading */
            break;
        }
        if (n == 0) {
            /* EOF - child process closed the pipe */
            break;
        }

        /* Print output in real-time */
        write(STDOUT_FILENO, buf, (size_t)n);

        /* Also save to buffer */
        if (output_size + (size_t)n >= output_capacity) {
            output_capacity *= 2;
            char *new_output = realloc(output, output_capacity);
            if (!new_output) {
                free(output);
                close(pipefd[0]);
                free_bootstrap_env(env, env_count);
                return ERROR(ERR_MEMORY, "Failed to resize bootstrap output buffer");
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
        free_bootstrap_env(env, env_count);
        return ERROR(ERR_FS, "Failed to wait for bootstrap process");
    }

    /* Check exit status */
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    /* Create result if requested */
    if (result) {
        bootstrap_result_t *res = calloc(1, sizeof(bootstrap_result_t));
        if (res) {
            res->exit_code = exit_code;
            res->output = output;
            res->failed = (exit_code != 0);
            *result = res;
        } else {
            free(output);
        }
    } else {
        free(output);
    }

    /* Cleanup */
    free_bootstrap_env(env, env_count);

    /* Return error if bootstrap failed */
    if (exit_code != 0) {
        return ERROR(ERR_INTERNAL,
                    "Bootstrap script failed with exit code %d", exit_code);
    }

    return NULL;
}

/**
 * Execute bootstrap for multiple profiles in order
 */
error_t *bootstrap_run_for_profiles(
    git_repository *repo,
    const char *repo_dir,
    struct profile_list *profiles,
    bool dry_run,
    bool stop_on_error
) {
    CHECK_NULL(repo);
    CHECK_NULL(repo_dir);
    CHECK_NULL(profiles);

    profile_list_t *plist = (profile_list_t *)profiles;
    const char *script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;

    /* Count scripts that exist */
    size_t script_count = 0;
    for (size_t i = 0; i < plist->count; i++) {
        if (bootstrap_exists(repo, plist->profiles[i].name, script_name)) {
            script_count++;
        }
    }

    if (script_count == 0) {
        printf("No bootstrap scripts found in enabled profiles.\n");
        return NULL;
    }

    /* Build space-separated list of all profiles */
    char **profile_names = malloc(plist->count * sizeof(char *));
    if (!profile_names) {
        return ERROR(ERR_MEMORY, "Failed to allocate profile names array");
    }

    for (size_t i = 0; i < plist->count; i++) {
        profile_names[i] = plist->profiles[i].name;
    }

    char *all_profiles_str = str_join(profile_names, plist->count, " ");
    free(profile_names);

    if (!all_profiles_str) {
        return ERROR(ERR_MEMORY, "Failed to join profile names");
    }

    /* Execute scripts in order */
    size_t executed = 0;
    error_t *last_error = NULL;

    for (size_t i = 0; i < plist->count; i++) {
        profile_t *profile = &plist->profiles[i];

        /* Check if bootstrap script exists */
        if (!bootstrap_exists(repo, profile->name, script_name)) {
            continue;
        }

        executed++;

        /* Get script path */
        char *script_path = NULL;
        error_t *err = bootstrap_get_path(repo_dir, profile->name, script_name, &script_path);
        if (err) {
            if (stop_on_error) {
                free(all_profiles_str);
                return error_wrap(err, "Failed to get bootstrap script path for %s", profile->name);
            }
            fprintf(stderr, "Warning: Failed to get bootstrap path for %s\n", profile->name);
            error_free(err);
            continue;
        }

        printf("\n[%zu/%zu] Running %s/%s...\n",
               executed, script_count, profile->name, script_name);

        if (dry_run) {
            printf("  (dry-run) Would execute: %s\n", script_path);
            free(script_path);
            continue;
        }

        /* Create context */
        bootstrap_context_t ctx = {
            .repo_dir = repo_dir,
            .profile_name = profile->name,
            .all_profiles = all_profiles_str,
            .dry_run = dry_run
        };

        /* Execute bootstrap */
        bootstrap_result_t *result = NULL;
        err = bootstrap_execute(script_path, &ctx, &result);
        free(script_path);

        if (err) {
            printf("✗ Failed");

            /* Show exit code if available from result */
            if (result && result->exit_code != 0) {
                printf(" (exit code %d)", result->exit_code);
            }
            printf("\n");

            /* Show error details */
            fprintf(stderr, "Error: %s\n", error_message(err));

            if (result) {
                bootstrap_result_free(result);
            }

            if (stop_on_error) {
                free(all_profiles_str);
                return error_wrap(err, "Bootstrap failed for profile %s", profile->name);
            }

            fprintf(stderr, "Warning: Continuing despite failure in profile '%s'\n", profile->name);
            /* Free previous error and save current error for later */
            if (last_error) {
                error_free(last_error);
            }
            last_error = err;  /* Transfer ownership - don't free err */
            continue;
        }

        printf("✓ Complete\n");

        if (result) {
            bootstrap_result_free(result);
        }
    }

    free(all_profiles_str);

    if (last_error && !stop_on_error) {
        printf("\nWarning: Some bootstrap scripts failed\n");
        error_free(last_error);
    }

    return NULL;
}

/**
 * Free bootstrap result
 */
void bootstrap_result_free(bootstrap_result_t *result) {
    if (!result) {
        return;
    }

    free(result->output);
    free(result);
}

/**
 * Create bootstrap context
 */
bootstrap_context_t *bootstrap_context_create(
    const char *repo_dir,
    const char *profile_name,
    const char *all_profiles
) {
    /* Validate required parameters */
    if (!repo_dir || !profile_name) {
        return NULL;
    }

    bootstrap_context_t *ctx = calloc(1, sizeof(bootstrap_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->repo_dir = repo_dir;
    ctx->profile_name = profile_name;
    ctx->all_profiles = all_profiles;  /* Optional - can be NULL */
    ctx->dry_run = false;

    return ctx;
}

/**
 * Free bootstrap context
 */
void bootstrap_context_free(bootstrap_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Note: We don't free the strings themselves as they're not owned by the context */
    free(ctx);
}
