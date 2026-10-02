/**
 * hooks.c - Hook execution system implementation
 */

#include "utils/hooks.h"

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
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
    HOOK_PRE_SYNC,
    HOOK_POST_SYNC,
} hook_type_t;

/* Hook environment. Pointers are borrowed from the configuration, the invocation
 * and its backing strings; this struct is stack-allocated in hook_fire and lives
 * only for the duration of one hook_execute call. */
typedef struct {
    const char *repo_dir;
    const char *command;
    const char *profile;
    char *const *files;
    size_t file_count;
    char *const *extras;
    bool dry_run;
} hook_context_t;

/* --- Static dispatch tables --------------------------------------------- */

static const char *const HOOK_NAMES[] = {
    [HOOK_PRE_ADD] = "pre-add",
    [HOOK_POST_ADD] = "post-add",
    [HOOK_PRE_REMOVE] = "pre-remove",
    [HOOK_POST_REMOVE] = "post-remove",
    [HOOK_PRE_APPLY] = "pre-apply",
    [HOOK_POST_APPLY] = "post-apply",
    [HOOK_PRE_UPDATE] = "pre-update",
    [HOOK_POST_UPDATE] = "post-update",
    [HOOK_PRE_SYNC] = "pre-sync",
    [HOOK_POST_SYNC] = "post-sync",
};

static const char *hook_type_name(hook_type_t type) {
    CHECK_ARG(
        (size_t) type < sizeof(HOOK_NAMES) / sizeof(HOOK_NAMES[0]),
        "a hook type no name is kept for"
    );
    return HOOK_NAMES[type];
}

/**
 * Check whether the given hook type is enabled in config.
 */
static bool hook_is_enabled(const config_t *config, hook_type_t type) {
    switch (type) {
        case HOOK_PRE_ADD:     return config->pre_add;
        case HOOK_POST_ADD:    return config->post_add;
        case HOOK_PRE_REMOVE:  return config->pre_remove;
        case HOOK_POST_REMOVE: return config->post_remove;
        case HOOK_PRE_APPLY:   return config->pre_apply;
        case HOOK_POST_APPLY:  return config->post_apply;
        case HOOK_PRE_UPDATE:  return config->pre_update;
        case HOOK_POST_UPDATE: return config->post_update;
        case HOOK_PRE_SYNC:    return config->pre_sync;
        case HOOK_POST_SYNC:   return config->post_sync;
    }

    return false;
}

/**
 * The hook's environment, a string array in `arena`: the DOTTA_* surface, the
 * command's extras, then the process's own environment with its DOTTA_* left
 * out, so the surface above cannot be shadowed. An envp as it stands — it always
 * holds DOTTA_DRY_RUN and DOTTA_FILE_COUNT, so its spine exists and is ended.
 */
static void hook_env(const hook_context_t *context, arena_t *arena, string_array_t *env) {
    extern char **environ;

    string_array_init(env, arena);

    /* DOTTA_* surface — the store's directory, two optional, two always-on, then
     * per-file. */
    string_array_pushf(env, "DOTTA_REPO_DIR=%s", context->repo_dir);
    if (context->command) string_array_pushf(env, "DOTTA_COMMAND=%s", context->command);
    if (context->profile) string_array_pushf(env, "DOTTA_PROFILE=%s", context->profile);

    string_array_pushf(env, "DOTTA_DRY_RUN=%s", context->dry_run ? "1" : "0");
    string_array_pushf(env, "DOTTA_FILE_COUNT=%zu", context->file_count);

    /* Indexed file variables: DOTTA_FILE_0, DOTTA_FILE_1, ... */
    for (size_t i = 0; i < context->file_count; i++) {
        string_array_pushf(env, "DOTTA_FILE_%zu=%s", i, context->files[i]);
    }

    /* Per-command extras (e.g. DOTTA_REMOTE for sync). Appended before the environ
     * pass-through so the DOTTA_* filter at the next step doesn't shadow them
     * with stale process-env values. */
    for (char *const *e = context->extras; e && *e; e++) string_array_push(env, *e);

    /* Copy system environment variables (PATH, HOME, etc.) — DOTTA_* are skipped
     * so our authoritative surface above isn't shadowed. */
    for (char **e = environ; *e; e++) {
        if (str_starts_with(*e, "DOTTA_")) continue;
        string_array_push(env, *e);
    }
}

/**
 * Execute hook script via the unified process primitive.
 *
 * Builds the hook environment, then delegates fork/exec/timeout/reap to
 * process_run(). Composes a domain-specific error from the result fields (exec
 * failure, timeout, signal, non-zero exit). When the caller passes a non-NULL
 * `result_out`, captured stdout/stderr is transferred into it for downstream
 * printing on failure.
 *
 * Returns NULL on success or if the hook is disabled/missing. Returns error if
 * the hook fails (exec, timeout, exit-code, signal) or if the primitive itself
 * failed.
 */
static error_t hook_execute(
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

    /* The hook's path and the spawn's environment, in a frame of the call's own:
     * the path read by the checks below and the child's exec, the environment
     * by the child at its exec, both dropped with the frame once the hook has
     * run. The directory is the one the configuration settled (utils/config.h). */
    arena_t *frame = arena_create(0);
    const char *hook_path = str_path_join(frame, config->hooks_dir, hook_type_name(type));
    error_t err = NULL;

    /* Missing hook is not an error — silently skip. */
    if (!fs_file_exists(hook_path)) goto cleanup;

    /* Not a refusal the invoker met: fs_is_executable asks faccessat(X_OK) as
     * the running user — the identity process_run will exec the hook under —
     * and this is its clean no. ERR_PERMISSION is a refusal an identity met
     * (base/error.h); a mode bit is not one, and a hook that did not run is the
     * class its four siblings below are in. The check earns its place ahead of
     * the exec by the message it makes: exec's own EACCES would reach the reader
     * as "Permission denied", the reading this class exists to keep honest. The
     * path is named because hooks_dir is the config's to choose and the type
     * alone is not something a reader can act on. */
    if (!fs_is_executable(hook_path)) {
        err = ERROR(
            ERR_INTERNAL, "Hook '%s' at '%s' is not executable",
            hook_type_name(type), hook_path
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

    string_array_t env;
    hook_env(context, frame, &env);

    char *argv[] = { (char *) hook_path, NULL };  /* execve's type; never written */
    process_spec_t spec = {
        .argv              = argv,
        .envp              = env.entries,
        .stdin_policy      = PROCESS_STDIN_DEVNULL,
        .capture           = (result_out != NULL),
        .stream_fd         = -1,
        .work_dir          = NULL,
        .work_dir_fallback = NULL,
        .timeout_seconds   = config->hook_timeout,
        .pgrp_policy       = PROCESS_PGRP_NEW,
    };

    process_result_t result = { 0 };
    err = process_run(&spec, &result);
    if (err) {
        process_result_deinit(&result);
        goto cleanup;
    }

    /* Map result fields to a domain-specific error. exec_failed is checked first
     * because it carries the most specific reason (errno from execve / chdir /
     * dup2). The 126/127 special-cases present in the legacy implementation are
     * intentionally absent: with exec_failed in place, those exit codes only
     * signal the script's own internal failures, which fall through to the generic
     * "exit code N" branch. */
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

    /* Transfer ownership to caller if requested. Move the whole struct so the
     * caller observes captured output even on failure (printed via
     * print_hook_output). The local `result` is disposed afterwards; with output
     * set NULL, dispose is a no-op on the buffer. */
    if (result_out) {
        *result_out = result;
        result.output = NULL;
    }

    process_result_deinit(&result);

cleanup:
    arena_free(frame);

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
        case HOOK_CMD_SYNC:   return "sync";
    }
    CHECK_ARG(false, "a hook command no enumerator names");
}

static hook_type_t pre_type_for(hook_cmd_t cmd) {
    switch (cmd) {
        case HOOK_CMD_ADD:    return HOOK_PRE_ADD;
        case HOOK_CMD_REMOVE: return HOOK_PRE_REMOVE;
        case HOOK_CMD_APPLY:  return HOOK_PRE_APPLY;
        case HOOK_CMD_UPDATE: return HOOK_PRE_UPDATE;
        case HOOK_CMD_SYNC:   return HOOK_PRE_SYNC;
    }
    CHECK_ARG(false, "a hook command no enumerator names");
}

static hook_type_t post_type_for(hook_cmd_t cmd) {
    switch (cmd) {
        case HOOK_CMD_ADD:    return HOOK_POST_ADD;
        case HOOK_CMD_REMOVE: return HOOK_POST_REMOVE;
        case HOOK_CMD_APPLY:  return HOOK_POST_APPLY;
        case HOOK_CMD_UPDATE: return HOOK_POST_UPDATE;
        case HOOK_CMD_SYNC:   return HOOK_POST_SYNC;
    }
    CHECK_ARG(false, "a hook command no enumerator names");
}

static void print_hook_output(
    output_t *out, const process_result_t *result
) {
    if (result && result->output && result->output_len > 0) {
        /* The hook's bytes are a payload, written as they are — its colours among
         * them, as git passes a hook's output on (base/output.h output_write) */
        output_print(out, OUTPUT_NORMAL, "Hook output:\n");
        output_write(
            out, OUTPUT_NORMAL, OUTPUT_COLOR_RESET, result->output, result->output_len
        );
        output_endline(out, OUTPUT_NORMAL);
        /* The capture kept the hook's first bytes (sys/process.h): what it dropped
         * is counted, never shown. */
        if (result->output_dropped > 0) {
            output_print(
                out, OUTPUT_NORMAL, "... and %zu more bytes\n",
                result->output_dropped
            );
        }
    }
}

/**
 * Stack-build a context from the configuration and the invocation and execute
 * the hook. The caller stack-allocates `out_result` and is responsible for calling
 * process_result_deinit() on every path.
 */
static error_t hook_fire(
    const config_t *config,
    const hook_invocation_t *inv,
    hook_type_t type,
    process_result_t *out_result
) {
    const hook_context_t ctx = {
        .repo_dir   = config->repo_dir,
        .command    = cmd_name(inv->cmd),
        .profile    = inv->profile,
        .files      = inv->files,
        .file_count = inv->file_count,
        .extras     = inv->extras,
        .dry_run    = inv->dry_run,
    };

    return hook_execute(config, type, &ctx, out_result);
}

error_t hook_fire_pre(
    const config_t *config,
    output_t *out,
    const hook_invocation_t *inv
) {
    CHECK_NULL(config);
    CHECK_NULL(inv);

    process_result_t result = { 0 };
    error_t err = hook_fire(config, inv, pre_type_for(inv->cmd), &result);

    if (err) {
        print_hook_output(out, &result);
        process_result_deinit(&result);
        return error_wrap(err, "Pre-%s hook failed", cmd_name(inv->cmd));
    }
    process_result_deinit(&result);
    return NULL;
}

void hook_fire_post(
    const config_t *config,
    output_t *out,
    const hook_invocation_t *inv
) {
    CHECK_NULL(config);
    CHECK_NULL(inv);

    if (inv->dry_run) return;

    process_result_t result = { 0 };
    error_t err = hook_fire(config, inv, post_type_for(inv->cmd), &result);

    if (err) {
        output_warning(
            out, OUTPUT_NORMAL, "Post-%s hook failed: %s",
            cmd_name(inv->cmd), error_message(err)
        );
        print_hook_output(out, &result);
    }
    process_result_deinit(&result);
}
