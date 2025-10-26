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
#include "utils/buffer.h"
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
 * Extract bootstrap script from Git blob to temporary file
 *
 * Creates a secure temporary file with executable permissions and writes
 * the bootstrap script content from the profile's Git tree.
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param script_name Script filename (default: ".bootstrap")
 * @param out_temp_path Output: path to temporary file (caller must free and unlink)
 * @return Error or NULL on success
 */
error_t *bootstrap_extract_to_temp(
    git_repository *repo,
    const char *profile_name,
    const char *script_name,
    char **out_temp_path
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_temp_path);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Declare resources for cleanup */
    error_t *err = NULL;
    git_tree *tree = NULL;
    git_blob *blob = NULL;
    char *ref_name = NULL;
    char *temp_path = NULL;
    int fd = -1;

    /* Build ref name */
    ref_name = str_format("refs/heads/%s", profile_name);
    if (!ref_name) {
        err = ERROR(ERR_MEMORY, "Failed to allocate ref name");
        goto cleanup;
    }

    /* Load tree from profile branch */
    err = gitops_load_tree(repo, ref_name, &tree);
    if (err) {
        err = error_wrap(err, "Failed to load tree from profile '%s'", profile_name);
        goto cleanup;
    }

    /* Find bootstrap script in tree */
    const git_tree_entry *entry = git_tree_entry_byname(tree, script_name);
    if (!entry) {
        err = ERROR(ERR_NOT_FOUND, "Bootstrap script not found in profile '%s'", profile_name);
        goto cleanup;
    }

    /* Load blob */
    const git_oid *oid = git_tree_entry_id(entry);
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    const unsigned char *content = git_blob_rawcontent(blob);
    size_t size = git_blob_rawsize(blob);

    /* Validate shebang */
    if (size < 2 || content[0] != '#' || content[1] != '!') {
        err = ERROR(ERR_INVALID_ARG,
                   "Bootstrap script must start with shebang (#!): %s", script_name);
        goto cleanup;
    }

    /* Create secure temporary file */
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) {
        tmpdir = "/tmp";
    }

    temp_path = str_format("%s/dotta-bootstrap-XXXXXX", tmpdir);
    if (!temp_path) {
        err = ERROR(ERR_MEMORY, "Failed to allocate temporary file path");
        goto cleanup;
    }

    fd = mkstemp(temp_path);
    if (fd < 0) {
        err = ERROR(ERR_FS, "Failed to create temporary file");
        goto cleanup;
    }

    /* Write blob content to temp file */
    ssize_t written = write(fd, content, size);
    if (written < 0 || (size_t)written != size) {
        err = ERROR(ERR_FS, "Failed to write bootstrap script to temporary file");
        goto cleanup;
    }

    /* Set executable permissions (owner only) */
    if (fchmod(fd, 0700) != 0) {
        err = ERROR(ERR_FS, "Failed to set executable permissions on bootstrap script");
        goto cleanup;
    }

    close(fd);
    fd = -1;

    /* Success - transfer ownership of temp_path to caller */
    *out_temp_path = temp_path;
    temp_path = NULL;
    err = NULL;

cleanup:
    if (fd >= 0) close(fd);
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    if (blob) git_blob_free(blob);
    if (tree) git_tree_free(tree);
    if (ref_name) free(ref_name);

    return err;
}

/**
 * Read bootstrap script content from Git blob
 *
 * @param repo Repository (must not be NULL)
 * @param profile_name Profile name (must not be NULL)
 * @param script_name Script filename (default: ".bootstrap")
 * @param out_content Output: buffer containing script content (caller must free)
 * @return Error or NULL on success
 */
error_t *bootstrap_read_content(
    git_repository *repo,
    const char *profile_name,
    const char *script_name,
    buffer_t **out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);
    CHECK_NULL(out_content);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Declare resources for cleanup */
    error_t *err = NULL;
    git_tree *tree = NULL;
    git_blob *blob = NULL;
    char *ref_name = NULL;
    buffer_t *content_buf = NULL;

    /* Build ref name */
    ref_name = str_format("refs/heads/%s", profile_name);
    if (!ref_name) {
        err = ERROR(ERR_MEMORY, "Failed to allocate ref name");
        goto cleanup;
    }

    /* Load tree from profile branch */
    err = gitops_load_tree(repo, ref_name, &tree);
    if (err) {
        err = error_wrap(err, "Failed to load tree from profile '%s'", profile_name);
        goto cleanup;
    }

    /* Find bootstrap script in tree */
    const git_tree_entry *entry = git_tree_entry_byname(tree, script_name);
    if (!entry) {
        err = ERROR(ERR_NOT_FOUND, "Bootstrap script not found in profile '%s'", profile_name);
        goto cleanup;
    }

    /* Load blob */
    const git_oid *oid = git_tree_entry_id(entry);
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    const unsigned char *content = git_blob_rawcontent(blob);
    size_t size = git_blob_rawsize(blob);

    /* Allocate buffer and copy content */
    content_buf = buffer_create();
    if (!content_buf) {
        err = ERROR(ERR_MEMORY, "Failed to allocate buffer for bootstrap content");
        goto cleanup;
    }

    if (size > 0) {
        err = buffer_append(content_buf, content, size);
        if (err) {
            err = error_wrap(err, "Failed to append content to buffer");
            goto cleanup;
        }
    }

    /* Success - transfer ownership to caller */
    *out_content = content_buf;
    content_buf = NULL;
    err = NULL;

cleanup:
    if (content_buf) buffer_free(content_buf);
    if (blob) git_blob_free(blob);
    if (tree) git_tree_free(tree);
    if (ref_name) free(ref_name);

    return err;
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
 *
 * Executes a bootstrap script from a temporary file. The script is expected
 * to have already been extracted and validated by bootstrap_extract_to_temp().
 *
 * Working directory: $HOME if accessible, otherwise repository root (repo_dir).
 * This provides a natural context for bootstrap operations (package installation,
 * user environment setup) while ensuring robustness in edge cases.
 *
 * Environment: DOTTA_REPO_DIR, DOTTA_PROFILE, DOTTA_PROFILES, DOTTA_DRY_RUN
 *
 * @param script_path Path to bootstrap script (must not be NULL)
 * @param context Execution context (must not be NULL)
 * @param result Optional result struct (can be NULL)
 * @return Error or NULL on success
 */
error_t *bootstrap_execute(
    const char *script_path,
    const bootstrap_context_t *context,
    bootstrap_result_t **result
) {
    CHECK_NULL(script_path);
    CHECK_NULL(context);

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

    /* Working directory is repo root (not profile subdirectory) */
    const char *work_dir = context->repo_dir;

    /* Fork and execute bootstrap */
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        free_bootstrap_env(env, env_count);
        return ERROR(ERR_FS, "Failed to fork for bootstrap execution");
    }

    if (pid == 0) {
        /* Child process */
        close(pipefd[0]); /* Close read end */

        /* Redirect stdout and stderr to pipe */
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        /* Change to working directory: HOME (preferred) or repo root (fallback)
         *
         * Rationale: Bootstrap scripts typically install packages, configure
         * user environment, and create directories - operations that naturally
         * assume $HOME as the starting point. If $HOME is unavailable (rare
         * edge case: daemon context, broken environment), fall back to repo
         * root for maximum robustness. If both fail, continue in current
         * directory (graceful degradation - most bootstrap operations are
         * location-independent). */
        const char *home = getenv("HOME");
        if (home && chdir(home) == 0) {
            /* Working from HOME - natural for bootstrap operations */
        } else if (work_dir && chdir(work_dir) == 0) {
            /* Fallback to repo root - guaranteed to exist */
        }
        /* If both fail, stay in current directory (graceful degradation) */

        /* Execute bootstrap with environment */
        char *args[] = { (char *)script_path, NULL };
        execve(script_path, args, env);

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

        printf("[%zu/%zu] Running %s/%s...\n",
               executed, script_count, profile->name, script_name);

        if (dry_run) {
            printf("  (dry-run) Would execute bootstrap for profile '%s'\n", profile->name);
            continue;
        }

        /* Extract script to temporary file */
        char *temp_path = NULL;
        error_t *err = bootstrap_extract_to_temp(repo, profile->name, script_name, &temp_path);
        if (err) {
            if (stop_on_error) {
                free(all_profiles_str);
                return error_wrap(err, "Failed to extract bootstrap script for %s", profile->name);
            }
            fprintf(stderr, "Warning: Failed to extract bootstrap for %s: %s\n",
                    profile->name, error_message(err));
            error_free(err);
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
        err = bootstrap_execute(temp_path, &ctx, &result);

        /* Clean up temporary file */
        if (temp_path) {
            unlink(temp_path);
            free(temp_path);
        }

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
