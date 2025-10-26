/**
 * bootstrap.c - Bootstrap script execution system implementation
 */

#include "bootstrap.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "utils/buffer.h"
#include "utils/string.h"

/* Exit codes for bootstrap script execution */
#define EXIT_CODE_TIMEOUT 124              /* Standard timeout exit code */
#define EXIT_CODE_CANNOT_EXECUTE 126       /* Command invoked cannot execute */
#define EXIT_CODE_NOT_FOUND 127            /* Command not found */

/* Bootstrap execution timeout (10 minutes) */
#define BOOTSTRAP_TIMEOUT_SECONDS 600

/* Poll interval for timeout checks (500ms) */
#define TIMEOUT_POLL_INTERVAL_MS 500

/**
 * Validate script name to prevent path traversal
 *
 * @param script_name Script name to validate
 * @return Error or NULL if valid
 */
static error_t *validate_script_name(const char *script_name) {
    if (!script_name || *script_name == '\0') {
        return ERROR(ERR_INVALID_ARG, "Script name cannot be empty");
    }

    /* Check for path separators to prevent directory traversal */
    if (strchr(script_name, '/') || strchr(script_name, '\\')) {
        return ERROR(ERR_INVALID_ARG,
                    "Script name cannot contain path separators: %s", script_name);
    }

    /* Check for parent directory references */
    if (strcmp(script_name, ".") == 0 || strcmp(script_name, "..") == 0) {
        return ERROR(ERR_INVALID_ARG,
                    "Script name cannot be '.' or '..': %s", script_name);
    }

    return NULL;
}

/**
 * Validate profile name for safe use in git refs
 *
 * @param profile_name Profile name to validate
 * @return Error or NULL if valid
 */
static error_t *validate_profile_name(const char *profile_name) {
    if (!profile_name || *profile_name == '\0') {
        return ERROR(ERR_INVALID_ARG, "Profile name cannot be empty");
    }

    /* Git ref name rules - simplified validation */
    const char *p = profile_name;
    while (*p) {
        /* Check for dangerous characters */
        if (*p == '\n' || *p == '\r' || *p == '\0') {
            return ERROR(ERR_INVALID_ARG,
                        "Profile name contains invalid characters");
        }
        /* Disallow control characters */
        if (iscntrl((unsigned char)*p)) {
            return ERROR(ERR_INVALID_ARG,
                        "Profile name contains control characters");
        }
        /* Check for problematic sequences */
        if (p[0] == '.' && p[1] == '.') {
            return ERROR(ERR_INVALID_ARG,
                        "Profile name cannot contain '..'");
        }
        p++;
    }

    /* Check for leading/trailing dots or slashes */
    if (profile_name[0] == '.' || profile_name[strlen(profile_name) - 1] == '.') {
        return ERROR(ERR_INVALID_ARG,
                    "Profile name cannot start or end with '.'");
    }

    return NULL;
}

/**
 * Validate shebang line
 *
 * @param content Script content
 * @param size Content size
 * @return Error or NULL if valid
 */
static error_t *validate_shebang(const unsigned char *content, size_t size) {
    if (size < 3) {
        return ERROR(ERR_INVALID_ARG,
                    "Bootstrap script too small (must have shebang line)");
    }

    /* Check shebang start */
    if (content[0] != '#' || content[1] != '!') {
        return ERROR(ERR_INVALID_ARG,
                    "Bootstrap script must start with shebang (#!)");
    }

    /* Find end of shebang line */
    size_t shebang_end = 2;
    while (shebang_end < size && content[shebang_end] != '\n') {
        shebang_end++;
    }

    /* Validate shebang has interpreter path */
    if (shebang_end == 2) {
        return ERROR(ERR_INVALID_ARG,
                    "Shebang line must specify interpreter path");
    }

    /* Extract interpreter path (skip #! and whitespace) */
    size_t path_start = 2;
    while (path_start < shebang_end && isspace(content[path_start])) {
        path_start++;
    }

    if (path_start >= shebang_end) {
        return ERROR(ERR_INVALID_ARG,
                    "Shebang line must specify interpreter path");
    }

    /* Verify it looks like an absolute path */
    if (content[path_start] != '/') {
        return ERROR(ERR_INVALID_ARG,
                    "Shebang interpreter must be an absolute path (start with /)");
    }

    return NULL;
}

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

    /* Validate inputs */
    error_t *err = validate_profile_name(profile_name);
    if (err) {
        error_free(err);
        return false;
    }

    err = validate_script_name(script_name);
    if (err) {
        error_free(err);
        return false;
    }

    /* Check if profile branch exists */
    bool exists = false;
    err = gitops_branch_exists(repo, profile_name, &exists);
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

    /* Validate inputs */
    error_t *err_validate = validate_profile_name(profile_name);
    if (err_validate) {
        return err_validate;
    }

    err_validate = validate_script_name(script_name);
    if (err_validate) {
        return err_validate;
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
    err = validate_shebang(content, size);
    if (err) {
        err = error_wrap(err, "Invalid bootstrap script '%s' in profile '%s'",
                        script_name, profile_name);
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

    /* Write blob content to temp file
     * Note: write() may return less than requested (partial write) or be
     * interrupted by signals (EINTR). Loop until all bytes are written. */
    size_t bytes_written = 0;
    while (bytes_written < size) {
        ssize_t n = write(fd, content + bytes_written, size - bytes_written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal, retry */
            }
            err = ERROR(ERR_FS, "Failed to write bootstrap script: %s", strerror(errno));
            goto cleanup;
        }
        bytes_written += (size_t)n;
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

    /* Validate inputs */
    error_t *err_validate = validate_profile_name(profile_name);
    if (err_validate) {
        return err_validate;
    }

    err_validate = validate_script_name(script_name);
    if (err_validate) {
        return err_validate;
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
            char *env_copy = strdup(*e);
            if (!env_copy) {
                /* strdup failed - cleanup and return NULL */
                goto cleanup_error;
            }
            env[count] = env_copy;
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
        if (env[i]) {
            free(env[i]);
        }
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
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0) {
            /* Cannot use ERROR() here - we're in child process.
             * Write directly to stderr before it's potentially redirected. */
            const char *msg = "Error: Failed to redirect output\n";
            (void)write(STDERR_FILENO, msg, strlen(msg));
            _exit(EXIT_CODE_CANNOT_EXECUTE);
        }
        close(pipefd[1]);

        /* Change to working directory: HOME (preferred) or repo root (fallback)
         *
         * Rationale: Bootstrap scripts typically install packages, configure
         * user environment, and create directories - operations that naturally
         * assume $HOME as the starting point. If $HOME is unavailable (rare
         * edge case: daemon context, broken environment), fall back to repo
         * root for maximum robustness. */
        const char *home = getenv("HOME");

        if (home && chdir(home) == 0) {
            /* Working from HOME - natural for bootstrap operations */
        } else if (work_dir && chdir(work_dir) == 0) {
            /* Fallback to repo root - guaranteed to exist */
            /* Inform script about fallback by printing to stderr */
            const char *msg = "Warning: HOME unavailable, using repository directory\n";
            (void)write(STDERR_FILENO, msg, strlen(msg));
        } else {
            /* Critical: both HOME and repo_dir failed */
            const char *msg = "Error: Failed to change to working directory\n";
            (void)write(STDERR_FILENO, msg, strlen(msg));
            _exit(EXIT_CODE_CANNOT_EXECUTE);
        }

        /* Execute bootstrap with environment */
        char *args[] = { (char *)script_path, NULL };
        execve(script_path, args, env);

        /* If execve returns, it failed */
        _exit(EXIT_CODE_NOT_FOUND);
    }

    /* Parent process */
    close(pipefd[1]); /* Close write end */

    /* Set pipe to non-blocking mode for timeout support */
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) {
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    /* Track elapsed time for timeout */
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);

    ssize_t n;
    char buf[1024];
    bool timed_out = false;
    bool process_exited = false;

    while (!process_exited) {
        /* Check for timeout */
        gettimeofday(&current_time, NULL);
        long elapsed_seconds = current_time.tv_sec - start_time.tv_sec;

        if (elapsed_seconds >= BOOTSTRAP_TIMEOUT_SECONDS) {
            timed_out = true;
            fprintf(stderr, "\nWarning: Bootstrap script exceeded timeout (%d seconds)\n",
                   BOOTSTRAP_TIMEOUT_SECONDS);

            /* Try graceful termination first */
            kill(pid, SIGTERM);
            sleep(2);

            /* Check if process terminated */
            int status;
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result == 0) {
                /* Still running - force kill */
                fprintf(stderr, "Warning: Forcefully terminating bootstrap script\n");
                kill(pid, SIGKILL);
            }
            break;
        }

        /* Use select() to wait for data with timeout */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(pipefd[0], &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = TIMEOUT_POLL_INTERVAL_MS * 1000;

        int select_result = select(pipefd[0] + 1, &read_fds, NULL, NULL, &timeout);

        if (select_result < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal, retry */
            }
            /* Real error */
            fprintf(stderr, "Warning: select() failed: %s\n", strerror(errno));
            break;
        }

        if (select_result == 0) {
            /* Timeout - check if process is still running */
            int status;
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                /* Process exited */
                process_exited = true;
                break;
            } else if (result < 0) {
                /* waitpid error */
                break;
            }
            /* Otherwise, continue waiting */
            continue;
        }

        /* Data available - read it */
        n = read(pipefd[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No data available right now */
                continue;
            }
            if (errno == EINTR) {
                continue;  /* Interrupted, retry */
            }
            /* Real error */
            fprintf(stderr, "Warning: Error reading bootstrap output: %s\n", strerror(errno));
            break;
        }

        if (n == 0) {
            /* EOF - child process closed the pipe */
            break;
        }

        /* Print output in real-time */
        (void)write(STDOUT_FILENO, buf, (size_t)n);
    }
    close(pipefd[0]);

    /* Wait for child process to fully terminate */
    int status = 0;
    int exit_code = 0;
    bool was_signaled = false;
    int signal_num = 0;

    if (timed_out) {
        /* Process was killed due to timeout - wait for it to terminate */
        int wait_result = waitpid(pid, &status, 0);
        if (wait_result == -1) {
            free_bootstrap_env(env, env_count);
            return ERROR(ERR_FS, "Bootstrap script timed out and failed to terminate");
        }
        /* Mark as timeout error */
        exit_code = EXIT_CODE_TIMEOUT;
    } else if (process_exited) {
        /* Process already exited - status was collected in WNOHANG call */
        /* Need to do final blocking wait to reap zombie */
        int wait_result = waitpid(pid, &status, 0);
        if (wait_result == -1 && errno != ECHILD) {
            free_bootstrap_env(env, env_count);
            return ERROR(ERR_FS, "Failed to wait for bootstrap process");
        }
    } else {
        /* Normal case - process hasn't exited yet, do blocking wait */
        if (waitpid(pid, &status, 0) == -1) {
            free_bootstrap_env(env, env_count);
            return ERROR(ERR_FS, "Failed to wait for bootstrap process");
        }
    }

    /* Check exit status - handle both normal exit and signal termination */
    if (!timed_out) {
        if (WIFEXITED(status)) {
            /* Normal exit */
            exit_code = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            /* Terminated by signal */
            was_signaled = true;
            signal_num = WTERMSIG(status);
            exit_code = 128 + signal_num;  /* Standard convention */
        } else {
            /* Unknown termination */
            exit_code = 1;
        }
    }

    /* Create result if requested */
    if (result) {
        bootstrap_result_t *res = calloc(1, sizeof(bootstrap_result_t));
        if (res) {
            res->exit_code = exit_code;
            res->failed = (exit_code != 0);
            *result = res;
        }
    }

    /* Cleanup */
    free_bootstrap_env(env, env_count);

    /* Return error if bootstrap failed */
    if (exit_code != 0) {
        if (timed_out) {
            return ERROR(ERR_INTERNAL,
                        "Bootstrap script exceeded timeout (%d seconds)",
                        BOOTSTRAP_TIMEOUT_SECONDS);
        } else if (was_signaled) {
            return ERROR(ERR_INTERNAL,
                        "Bootstrap script terminated by signal %d", signal_num);
        } else {
            return ERROR(ERR_INTERNAL,
                        "Bootstrap script failed with exit code %d", exit_code);
        }
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
    size_t failed_count = 0;
    char **failed_profiles = malloc(script_count * sizeof(char *));
    if (!failed_profiles) {
        free(all_profiles_str);
        return ERROR(ERR_MEMORY, "Failed to allocate failed profiles array");
    }

    for (size_t i = 0; i < plist->count; i++) {
        profile_t *profile = &plist->profiles[i];

        /* Check if bootstrap script exists */
        if (!bootstrap_exists(repo, profile->name, script_name)) {
            continue;
        }

        executed++;

        printf("[%zu/%zu] Running %s/%s...\n",
               executed, script_count, profile->name, script_name);

        /* In dry-run mode, validate the script but don't execute */
        if (dry_run) {
            /* Extract and validate script even in dry-run */
            char *temp_path = NULL;
            error_t *err = bootstrap_extract_to_temp(repo, profile->name, script_name, &temp_path);
            if (err) {
                printf("  ✗ (dry-run) Validation failed: %s\n", error_message(err));
                error_free(err);
                if (stop_on_error) {
                    free(all_profiles_str);
                    free(failed_profiles);
                    return ERROR(ERR_INVALID_ARG,
                                "Bootstrap script validation failed for %s", profile->name);
                }
                failed_profiles[failed_count++] = profile->name;
            } else {
                printf("  ✓ (dry-run) Would execute bootstrap for profile '%s'\n", profile->name);
                if (temp_path) {
                    unlink(temp_path);
                    free(temp_path);
                }
            }
            continue;
        }

        /* Extract script to temporary file */
        char *temp_path = NULL;
        error_t *err = bootstrap_extract_to_temp(repo, profile->name, script_name, &temp_path);
        if (err) {
            printf("  ✗ Failed to extract: %s\n", error_message(err));
            if (stop_on_error) {
                free(all_profiles_str);
                free(failed_profiles);
                return error_wrap(err, "Failed to extract bootstrap script for %s", profile->name);
            }
            error_free(err);
            failed_profiles[failed_count++] = profile->name;
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
            printf("  ✗ Failed");

            /* Show exit code if available from result */
            if (result && result->exit_code != 0) {
                printf(" (exit code %d)", result->exit_code);
            }
            printf("\n");

            /* Show error details */
            fprintf(stderr, "  Error: %s\n", error_message(err));

            if (result) {
                bootstrap_result_free(result);
            }

            if (stop_on_error) {
                free(all_profiles_str);
                free(failed_profiles);
                return error_wrap(err, "Bootstrap failed for profile %s", profile->name);
            }

            /* Track failed profile */
            failed_profiles[failed_count++] = profile->name;
            error_free(err);
            continue;
        }

        printf("  ✓ Complete\n");

        if (result) {
            bootstrap_result_free(result);
        }
    }

    free(all_profiles_str);

    /* Report failures if any occurred */
    if (failed_count > 0 && !stop_on_error) {
        printf("\n");
        fprintf(stderr, "Warning: %zu bootstrap script%s failed:\n",
               failed_count, failed_count == 1 ? "" : "s");
        for (size_t i = 0; i < failed_count; i++) {
            fprintf(stderr, "  - %s\n", failed_profiles[i]);
        }
    }

    free(failed_profiles);

    return NULL;
}

/**
 * Free bootstrap result
 */
void bootstrap_result_free(bootstrap_result_t *result) {
    if (!result) {
        return;
    }

    free(result);
}

