/**
 * hooks.c - Hook execution system implementation
 */

#include "utils/hooks.h"

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/process.h"

/* --- Internal types ------------------------------------------------------ */

/* Hook script name lookup. Also drives the pre/post mapping below. */
typedef enum {
    HOOK_PRE_ADD,
    HOOK_POST_ADD,
    HOOK_PRE_REMOVE,
    HOOK_POST_REMOVE,
    HOOK_PRE_APPLY,
    HOOK_POST_APPLY,
    HOOK_PRE_UPDATE,
    HOOK_POST_UPDATE,
} hook_type_t;

/* Hook environment. Pointers are borrowed from the invocation and its
 * backing strings; this struct is stack-allocated in hook_fire and
 * lives only for the duration of one hook_execute call. */
typedef struct {
    const char *repo_dir;
    const char *command;
    const char *profile;
    char *const *files;
    size_t file_count;
    bool dry_run;
} hook_context_t;

/* --- Static dispatch tables --------------------------------------------- */

static const char *HOOK_NAMES[] = {
    [HOOK_PRE_ADD] = "pre-add",
    [HOOK_POST_ADD] = "post-add",
    [HOOK_PRE_REMOVE] = "pre-remove",
    [HOOK_POST_REMOVE] = "post-remove",
    [HOOK_PRE_APPLY] = "pre-apply",
    [HOOK_POST_APPLY] = "post-apply",
    [HOOK_PRE_UPDATE] = "pre-update",
    [HOOK_POST_UPDATE] = "post-update",
};

static const char *hook_type_name(hook_type_t type) {
    if (type >= 0 && type < (sizeof(HOOK_NAMES) / sizeof(HOOK_NAMES[0]))) {
        return HOOK_NAMES[type];
    }
    return "unknown";
}

/**
 * Check whether the given hook type is enabled in config.
 */
static bool hook_is_enabled(const config_t *config, hook_type_t type) {
    if (!config) {
        return false;
    }

    switch (type) {
        case HOOK_PRE_ADD:     return config->pre_add;
        case HOOK_POST_ADD:    return config->post_add;
        case HOOK_PRE_REMOVE:  return config->pre_remove;
        case HOOK_POST_REMOVE: return config->post_remove;
        case HOOK_PRE_APPLY:   return config->pre_apply;
        case HOOK_POST_APPLY:  return config->post_apply;
        case HOOK_PRE_UPDATE:  return config->pre_update;
        case HOOK_POST_UPDATE: return config->post_update;
    }
    return false;
}

/**
 * Get hook script path
 */
static error_t *hook_get_path(
    const config_t *config,
    hook_type_t type,
    char **out
) {
    CHECK_NULL(config);
    CHECK_NULL(out);

    const char *hook_name = hook_type_name(type);
    if (strcmp(hook_name, "unknown") == 0) {
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
        (context->repo_dir ? 1 : 0) + (context->command ? 1 : 0) +
        (context->profile ? 1 : 0) + context->file_count + system_env_count;

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
            goto cleanup;
        }
        count++;
    }

    if (context->command) {
        env[count] = str_format("DOTTA_COMMAND=%s", context->command);
        if (!env[count]) {
            goto cleanup;
        }
        count++;
    }

    if (context->profile) {
        env[count] = str_format("DOTTA_PROFILE=%s", context->profile);
        if (!env[count]) {
            goto cleanup;
        }
        count++;
    }

    env[count] = str_format("DOTTA_DRY_RUN=%s", context->dry_run ? "1" : "0");
    if (!env[count]) {
        goto cleanup;
    }
    count++;

    env[count] = str_format("DOTTA_FILE_COUNT=%zu", context->file_count);
    if (!env[count]) {
        goto cleanup;
    }
    count++;

    /* Add indexed file variables: DOTTA_FILE_0, DOTTA_FILE_1, ... */
    if (context->files && context->file_count > 0) {
        for (size_t i = 0; i < context->file_count; i++) {
            env[count] = str_format("DOTTA_FILE_%zu=%s", i, context->files[i]);
            if (!env[count]) {
                goto cleanup;
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
                goto cleanup;
            }
            count++;
        }
    }

    /* NULL-terminate */
    env[count] = NULL;
    *env_count = count;

    return env;

cleanup:
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
 * Execute hook script via the unified process primitive.
 *
 * Builds the hook environment, then delegates fork/exec/timeout/reap
 * to process_run(). Composes a domain-specific error from the result
 * fields (exec failure, timeout, signal, non-zero exit). When the
 * caller passes a non-NULL `result_out`, captured stdout/stderr is
 * transferred into it for downstream printing on failure.
 *
 * Returns NULL on success or if the hook is disabled/missing.
 * Returns error if the hook fails (exec, timeout, exit-code, signal)
 * or if the primitive itself failed.
 */
static error_t *hook_execute(
    const config_t *config,
    hook_type_t type,
    const hook_context_t *context,
    process_result_t *result_out
) {
    CHECK_NULL(config);
    CHECK_NULL(context);

    if (!hook_is_enabled(config, type)) {
        return NULL;  /* Disabled - skip silently */
    }

    char *hook_path = NULL;
    char **env = NULL;
    size_t env_count = 0;
    error_t *err = NULL;

    err = hook_get_path(config, type, &hook_path);
    if (err) goto cleanup;

    /* Missing hook is not an error — silently skip. */
    if (!fs_file_exists(hook_path)) goto cleanup;

    if (!fs_is_executable(hook_path)) {
        err = ERROR(
            ERR_PERMISSION,
            "Hook '%s' is not executable", hook_type_name(type)
        );
        goto cleanup;
    }

    /* Sanity check: bound DOTTA_FILE_N env explosion. */
    if (context->file_count > 10000) {
        err = ERROR(
            ERR_INVALID_ARG,
            "Hook '%s': too many files in context (%zu, limit: 10000)",
            hook_type_name(type), context->file_count
        );
        goto cleanup;
    }

    env = build_hook_env(context, &env_count);
    if (!env) {
        err = ERROR(ERR_MEMORY, "Failed to build environment for hook");
        goto cleanup;
    }

    char *argv[] = { hook_path, NULL };
    process_spec_t spec = {
        .argv              = argv,
        .envp              = env,
        .stdin_policy      = PROCESS_STDIN_DEVNULL,
        .capture           = (result_out != NULL),
        .stream_fd         = -1,
        .work_dir          = NULL,
        .work_dir_fallback = NULL,
        .timeout_seconds   = config->hook_timeout > 0 ? config->hook_timeout : 0,
        .pgrp_policy       = PROCESS_PGRP_NEW,
    };

    process_result_t result = { 0 };
    err = process_run(&spec, &result);
    if (err) {
        process_result_dispose(&result);
        goto cleanup;
    }

    /* Map result fields to a domain-specific error. exec_failed is
     * checked first because it carries the most specific reason
     * (errno from execve / chdir / dup2). The 126/127 special-cases
     * present in the legacy implementation are intentionally absent:
     * with exec_failed in place, those exit codes only signal the
     * script's own internal failures, which fall through to the
     * generic "exit code N" branch. */
    if (result.exec_failed) {
        err = ERROR(
            ERR_INTERNAL, "Hook '%s' failed: exec error: %s",
            hook_type_name(type), strerror(result.exec_errno)
        );
    } else if (result.timed_out) {
        err = ERROR(
            ERR_INTERNAL, "Hook '%s' exceeded timeout of %d seconds",
            hook_type_name(type), config->hook_timeout
        );
    } else if (result.signal_num) {
        err = ERROR(
            ERR_INTERNAL, "Hook '%s' terminated by signal %d",
            hook_type_name(type), result.signal_num
        );
    } else if (result.exit_code != 0) {
        err = ERROR(
            ERR_INTERNAL, "Hook '%s' failed with exit code %d",
            hook_type_name(type), result.exit_code
        );
    }

    /* Transfer ownership to caller if requested. Move the whole
     * struct so the caller observes captured output even on failure
     * (printed via print_hook_output). The local `result` is
     * disposed afterwards; with output set NULL, dispose is a
     * no-op on the buffer. */
    if (result_out) {
        *result_out = result;
        result.output = NULL;
    }
    process_result_dispose(&result);

cleanup:
    if (env) free_hook_env(env, env_count);
    free(hook_path);
    return err;
}

/**
 * Invocation-based API (hook_fire_pre / hook_fire_post)
 */
static const char *cmd_name(hook_cmd_t cmd) {
    switch (cmd) {
        case HOOK_CMD_ADD:    return "add";
        case HOOK_CMD_REMOVE: return "remove";
        case HOOK_CMD_APPLY:  return "apply";
        case HOOK_CMD_UPDATE: return "update";
    }
    return "unknown";
}

static hook_type_t pre_type_for(hook_cmd_t cmd) {
    switch (cmd) {
        case HOOK_CMD_ADD:    return HOOK_PRE_ADD;
        case HOOK_CMD_REMOVE: return HOOK_PRE_REMOVE;
        case HOOK_CMD_APPLY:  return HOOK_PRE_APPLY;
        case HOOK_CMD_UPDATE: return HOOK_PRE_UPDATE;
    }
    return HOOK_PRE_ADD;
}

static hook_type_t post_type_for(hook_cmd_t cmd) {
    switch (cmd) {
        case HOOK_CMD_ADD:    return HOOK_POST_ADD;
        case HOOK_CMD_REMOVE: return HOOK_POST_REMOVE;
        case HOOK_CMD_APPLY:  return HOOK_POST_APPLY;
        case HOOK_CMD_UPDATE: return HOOK_POST_UPDATE;
    }
    return HOOK_POST_ADD;
}

static void print_hook_output(
    output_t *out, const process_result_t *result
) {
    if (result && result->output && result->output[0]) {
        output_print(
            out, OUTPUT_NORMAL, "Hook output:\n%s\n", result->output
        );
    }
}

/**
 * Stack-build a context from the invocation and execute the hook.
 * `repo_dir` is borrowed from the caller (ctx->repo_path in normal
 * flow). The caller stack-allocates `out_result` and is responsible
 * for calling process_result_dispose() on every path.
 */
static error_t *hook_fire(
    const config_t *config,
    const char *repo_dir,
    const hook_invocation_t *inv,
    hook_type_t type,
    process_result_t *out_result
) {
    const hook_context_t ctx = {
        .repo_dir   = repo_dir,
        .command    = cmd_name(inv->cmd),
        .profile    = inv->profile,
        .files      = inv->files,
        .file_count = inv->file_count,
        .dry_run    = inv->dry_run,
    };

    return hook_execute(config, type, &ctx, out_result);
}

error_t *hook_fire_pre(
    const config_t *config,
    output_t *out,
    const char *repo_dir,
    const hook_invocation_t *inv
) {
    CHECK_NULL(config);
    CHECK_NULL(inv);

    process_result_t result = { 0 };
    error_t *err = hook_fire(
        config, repo_dir, inv, pre_type_for(inv->cmd), &result
    );

    if (err) {
        print_hook_output(out, &result);
        process_result_dispose(&result);
        return error_wrap(err, "Pre-%s hook failed", cmd_name(inv->cmd));
    }
    process_result_dispose(&result);
    return NULL;
}

void hook_fire_post(
    const config_t *config,
    output_t *out,
    const char *repo_dir,
    const hook_invocation_t *inv
) {
    if (!config || !inv) return;
    if (inv->dry_run) return;

    process_result_t result = { 0 };
    error_t *err = hook_fire(
        config, repo_dir, inv, post_type_for(inv->cmd), &result
    );

    if (err) {
        output_warning(
            out, OUTPUT_NORMAL, "Post-%s hook failed: %s",
            cmd_name(inv->cmd), error_message(err)
        );
        print_hook_output(out, &result);
        error_free(err);
    }
    process_result_dispose(&result);
}
