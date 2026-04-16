/**
 * bootstrap.c - Bootstrap script execution system implementation
 */

#include "sys/bootstrap.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/string.h"
#include "sys/gitops.h"
#include "sys/process.h"

/* Bootstrap execution timeout (10 minutes) */
#define BOOTSTRAP_TIMEOUT_SECONDS 600

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
        return ERROR(
            ERR_INVALID_ARG,
            "Script name cannot contain path separators: %s", script_name
        );
    }

    /* Check for parent directory references */
    if (strcmp(script_name, ".") == 0 || strcmp(script_name, "..") == 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "Script name cannot be '.' or '..': %s", script_name
        );
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
        if (*p == '\n' || *p == '\r') {
            return ERROR(
                ERR_INVALID_ARG,
                "Profile name contains invalid characters"
            );
        }
        /* Disallow control characters */
        if (iscntrl((unsigned char) *p)) {
            return ERROR(
                ERR_INVALID_ARG,
                "Profile name contains control characters"
            );
        }
        /* Check for problematic sequences */
        if (p[0] == '.' && p[1] == '.') {
            return ERROR(
                ERR_INVALID_ARG,
                "Profile name cannot contain '..'"
            );
        }
        p++;
    }

    /* Check for leading/trailing dots or slashes */
    if (profile_name[0] == '.' || profile_name[strlen(profile_name) - 1] == '.') {
        return ERROR(
            ERR_INVALID_ARG,
            "Profile name cannot start or end with '.'"
        );
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
        return ERROR(
            ERR_INVALID_ARG,
            "Bootstrap script too small (must have shebang line)"
        );
    }

    /* Check shebang start */
    if (content[0] != '#' || content[1] != '!') {
        return ERROR(
            ERR_INVALID_ARG,
            "Bootstrap script must start with shebang (#!)"
        );
    }

    /* Find end of shebang line */
    size_t shebang_end = 2;
    while (shebang_end < size && content[shebang_end] != '\n') {
        shebang_end++;
    }

    /* Validate shebang has interpreter path */
    if (shebang_end == 2) {
        return ERROR(
            ERR_INVALID_ARG,
            "Shebang line must specify interpreter path"
        );
    }

    /* Extract interpreter path (skip #! and whitespace) */
    size_t path_start = 2;
    while (path_start < shebang_end && isspace(content[path_start])) {
        path_start++;
    }

    if (path_start >= shebang_end) {
        return ERROR(
            ERR_INVALID_ARG,
            "Shebang line must specify interpreter path"
        );
    }

    /* Verify it looks like an absolute path */
    if (content[path_start] != '/') {
        return ERROR(
            ERR_INVALID_ARG,
            "Shebang interpreter must be an absolute path (start with /)"
        );
    }

    return NULL;
}

/**
 * Validate bootstrap script content
 */
error_t *bootstrap_validate_content(const unsigned char *content, size_t size) {
    if (!content) {
        return ERROR(
            ERR_INVALID_ARG, "Script content cannot be NULL"
        );
    }
    return validate_shebang(content, size);
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

    /* Load tree from profile branch */
    git_tree *tree = NULL;
    err = gitops_load_branch_tree(repo, profile_name, &tree, NULL);
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
    void *content = NULL;
    char *temp_path = NULL;
    int fd = -1;

    /* Load tree from profile branch */
    err = gitops_load_branch_tree(repo, profile_name, &tree, NULL);
    if (err) {
        err = error_wrap(
            err, "Failed to load tree from profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* Find bootstrap script in tree */
    const git_tree_entry *entry = git_tree_entry_byname(tree, script_name);
    if (!entry) {
        err = ERROR(
            ERR_NOT_FOUND, "Bootstrap script not found in profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* Read blob content */
    size_t size = 0;
    err = gitops_read_blob_content(repo, git_tree_entry_id(entry), &content, &size);
    if (err) goto cleanup;

    /* Validate shebang */
    err = validate_shebang(content, size);
    if (err) {
        err = error_wrap(
            err, "Invalid bootstrap script '%s' in profile '%s'",
            script_name, profile_name
        );
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
        ssize_t n = write(fd, (char *) content + bytes_written, size - bytes_written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal, retry */
            }
            err = ERROR(
                ERR_FS, "Failed to write bootstrap script: %s",
                strerror(errno)
            );
            goto cleanup;
        }
        bytes_written += (size_t) n;
    }

    /* Set executable permissions (owner only) */
    if (fchmod(fd, 0700) != 0) {
        err = ERROR(
            ERR_FS, "Failed to set executable permissions on bootstrap script"
        );
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
    free(content);
    if (tree) git_tree_free(tree);

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
    buffer_t *out_content
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
    void *raw_content = NULL;
    buffer_t content_buf = BUFFER_INIT;

    /* Load tree from profile branch */
    err = gitops_load_branch_tree(repo, profile_name, &tree, NULL);
    if (err) {
        err = error_wrap(
            err, "Failed to load tree from profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* Find bootstrap script in tree */
    const git_tree_entry *entry = git_tree_entry_byname(tree, script_name);
    if (!entry) {
        err = ERROR(
            ERR_NOT_FOUND, "Bootstrap script not found in profile '%s'",
            profile_name
        );
        goto cleanup;
    }

    /* Read blob content */
    size_t size = 0;
    err = gitops_read_blob_content(repo, git_tree_entry_id(entry), &raw_content, &size);
    if (err) goto cleanup;

    /* Copy content into buffer */
    if (size > 0) {
        err = buffer_append(&content_buf, raw_content, size);
        if (err) {
            err = error_wrap(err, "Failed to append content to buffer");
            goto cleanup;
        }
    }

    /* Success - transfer to caller */
    *out_content = content_buf;
    content_buf = (buffer_t){ 0 };
    err = NULL;

cleanup:
    buffer_free(&content_buf);
    if (raw_content) free(raw_content);
    if (tree) git_tree_free(tree);

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
        if (env[i]) free(env[i]);
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
 * Execute bootstrap script via the unified process primitive.
 *
 * Builds the bootstrap environment, then delegates fork/exec/timeout/reap
 * to process_run(). Composes a domain-specific error from the result
 * fields. The exit code (when produced) is returned via the optional
 * out parameter regardless of whether the call succeeds or fails.
 */
error_t *bootstrap_execute(
    const char *script_path,
    const bootstrap_context_t *context,
    int *exit_code_out
) {
    CHECK_NULL(script_path);
    CHECK_NULL(context);

    if (exit_code_out) {
        *exit_code_out = 0;
    }

    size_t env_count = 0;
    char **env = build_bootstrap_env(context, &env_count);
    if (!env) {
        return ERROR(
            ERR_MEMORY, "Failed to build environment for bootstrap script"
        );
    }

    char *argv[] = { (char *) script_path, NULL };
    process_spec_t spec = {
        .argv              = argv,
        .envp              = env,
        .stdin_policy      = PROCESS_STDIN_INHERIT,
        .capture           = false,
        .stream_fd         = STDOUT_FILENO,
        .work_dir          = getenv("HOME"),
        .work_dir_fallback = context->repo_dir,
        .timeout_seconds   = BOOTSTRAP_TIMEOUT_SECONDS,
        .pgrp_policy       = PROCESS_PGRP_SHARED,
    };

    /* Flush our own buffered prints (e.g., the "[N/M] Running…" line)
     * so they reach stdout before the child's raw write() chunks land
     * on the same fd. Without this, redirected stdout interleaves the
     * child's output ahead of our progress line. */
    fflush(stdout);

    process_result_t result = { 0 };
    error_t *err = process_run(&spec, &result);
    free_bootstrap_env(env, env_count);

    if (exit_code_out) {
        *exit_code_out = result.exit_code;
    }

    if (err) {
        process_result_dispose(&result);
        return err;
    }

    error_t *script_err = NULL;
    if (result.exec_failed) {
        script_err = ERROR(
            ERR_INTERNAL, "Failed to exec bootstrap script: %s",
            strerror(result.exec_errno)
        );
    } else if (result.timed_out) {
        script_err = ERROR(
            ERR_INTERNAL, "Bootstrap script exceeded timeout (%d seconds)",
            BOOTSTRAP_TIMEOUT_SECONDS
        );
    } else if (result.signal_num) {
        script_err = ERROR(
            ERR_INTERNAL, "Bootstrap script terminated by signal %d",
            result.signal_num
        );
    } else if (result.exit_code != 0) {
        script_err = ERROR(
            ERR_INTERNAL, "Bootstrap script failed with exit code %d",
            result.exit_code
        );
    }

    process_result_dispose(&result);
    return script_err;
}

/**
 * Execute bootstrap for multiple profiles in order
 */
error_t *bootstrap_run_for_profiles(
    git_repository *repo,
    const char *repo_dir,
    const string_array_t *profiles,
    bool dry_run,
    bool stop_on_error
) {
    CHECK_NULL(repo);
    CHECK_NULL(repo_dir);
    CHECK_NULL(profiles);

    const char *script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;

    /* Count scripts that exist */
    size_t script_count = 0;
    for (size_t i = 0; i < profiles->count; i++) {
        if (bootstrap_exists(repo, profiles->items[i], script_name)) {
            script_count++;
        }
    }

    if (script_count == 0) {
        printf("No bootstrap scripts found in enabled profiles.\n");
        return NULL;
    }

    /* Build space-separated list of all profiles for environment variable */
    char *all_profiles = string_array_join(profiles, " ");
    if (!all_profiles) {
        return ERROR(ERR_MEMORY, "Failed to join profile names");
    }

    /* Execute scripts in order */
    size_t executed = 0;
    size_t failed_count = 0;
    const char **failed_profiles = malloc(script_count * sizeof(const char *));
    if (!failed_profiles) {
        free(all_profiles);
        return ERROR(ERR_MEMORY, "Failed to allocate failed profiles array");
    }

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile_name = profiles->items[i];

        /* Check if bootstrap script exists */
        if (!bootstrap_exists(repo, profile_name, script_name)) {
            continue;
        }

        executed++;

        printf(
            "[%zu/%zu] Running %s/%s...\n",
            executed, script_count, profile_name, script_name
        );

        /* In dry-run mode, validate the script but don't execute */
        if (dry_run) {
            /* Extract and validate script even in dry-run */
            char *temp_path = NULL;
            error_t *err = bootstrap_extract_to_temp(
                repo, profile_name, script_name, &temp_path
            );
            if (err) {
                printf(
                    "  ✗ (dry-run) Validation failed: %s\n",
                    error_message(err)
                );
                error_free(err);
                if (stop_on_error) {
                    free(all_profiles);
                    free(failed_profiles);
                    return ERROR(
                        ERR_INVALID_ARG,
                        "Bootstrap script validation failed for %s",
                        profile_name
                    );
                }
                failed_profiles[failed_count++] = profile_name;
            } else {
                printf(
                    "  ✓ (dry-run) Would execute bootstrap for profile '%s'\n",
                    profile_name
                );

                if (temp_path) {
                    unlink(temp_path);
                    free(temp_path);
                }
            }
            continue;
        }

        /* Extract script to temporary file */
        char *temp_path = NULL;
        error_t *err = bootstrap_extract_to_temp(
            repo, profile_name, script_name, &temp_path
        );
        if (err) {
            printf("  ✗ Failed to extract: %s\n", error_message(err));
            if (stop_on_error) {
                free(all_profiles);
                free(failed_profiles);
                return error_wrap(
                    err, "Failed to extract bootstrap script for %s",
                    profile_name
                );
            }
            error_free(err);
            failed_profiles[failed_count++] = profile_name;
            continue;
        }

        /* Create context */
        bootstrap_context_t ctx = {
            .repo_dir     = repo_dir,
            .profile_name = profile_name,
            .all_profiles = all_profiles,
            .dry_run      = dry_run
        };

        /* Execute bootstrap */
        int exit_code = 0;
        err = bootstrap_execute(temp_path, &ctx, &exit_code);

        /* Clean up temporary file */
        if (temp_path) {
            unlink(temp_path);
            free(temp_path);
        }

        if (err) {
            printf("  ✗ Failed");
            if (exit_code != 0) {
                printf(" (exit code %d)", exit_code);
            }
            printf("\n");

            /* Show error details */
            fprintf(stderr, "  Error: %s\n", error_message(err));

            if (stop_on_error) {
                free(all_profiles);
                free(failed_profiles);
                return error_wrap(
                    err, "Bootstrap failed for profile %s",
                    profile_name
                );
            }

            /* Track failed profile */
            failed_profiles[failed_count++] = profile_name;
            error_free(err);
            continue;
        }

        printf("  ✓ Complete\n");
    }

    free(all_profiles);

    /* Report and return error on partial failure */
    if (failed_count > 0) {
        printf("\n");
        fprintf(
            stderr, "Warning: %zu bootstrap script%s failed:\n",
            failed_count, failed_count == 1 ? "" : "s"
        );
        for (size_t i = 0; i < failed_count; i++) {
            fprintf(stderr, "  - %s\n", failed_profiles[i]);
        }
        free(failed_profiles);
        return ERROR(
            ERR_INTERNAL, "%zu of %zu bootstrap script%s failed",
            failed_count, script_count, failed_count == 1 ? "" : "s"
        );
    }

    free(failed_profiles);

    return NULL;
}
