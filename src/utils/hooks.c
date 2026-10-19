/**
 * hooks.c - Hook execution system implementation
 */

#include "utils/hooks.h"

#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "sys/filesystem.h"
#include "sys/process.h"
#include "utils/config.h"

/**
 * A hook's phase: the first word of its name, before its command's
 */
typedef enum {
    HOOK_PHASE_PRE,   /* pre-<command>: before the act, a failure the command's refusal */
    HOOK_PHASE_POST,  /* post-<command>: after the act, a failure warned; none on a dry run */
} hook_phase_t;

/**
 * What stands at a hook's name, as the exec will meet it
 *
 * Looked up with the raw calls, never sys/filesystem's second try as root: a
 * hook runs as the invoker (sys/identity.h identity_drop_child), so the invoker's
 * answer is the one that holds, under sudo as without it.
 */
typedef enum {
    HOOK_FOUND_ABSENT,    /* Nothing at the name, or a link to nothing: no hook */
    HOOK_FOUND_UNKNOWN,   /* The name cannot be looked up, nor any other in its directory */
    HOOK_FOUND_IGNORED,   /* What the exec would refuse: no regular file, no execute bit */
    HOOK_FOUND_RUNNABLE,  /* A regular file the invoker may execute */
} hook_found_t;

/* The command's word: its hooks' names (pre-<word>, post-<word>) and DOTTA_COMMAND */
static const char *hook_word(hook_cmd_t cmd) {
    switch (cmd) {
        case HOOK_CMD_ADD:    return "add";
        case HOOK_CMD_REMOVE: return "remove";
        case HOOK_CMD_APPLY:  return "apply";
        case HOOK_CMD_UPDATE: return "update";
        case HOOK_CMD_SYNC:   return "sync";
    }

    CHECK_ARG(false, "a hook command no enumerator names");
}

/**
 * What stands at a hook's path (hook_found_t) — the file is the switch, git's
 * (lib/git/hook.c find_hook) — and, where it is unknown or ignored, the reason
 * its notice gives, made in `arena` where it names the kind that stands
 */
static hook_found_t hook_find(const char *path, arena_t *arena, const char **reason) {
    /* The name first, never followed: a directory that will not let it be looked
     * up hides every name in it, a hook that is not there among them, so that
     * is the directory's to say, never a hook's */
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) return HOOK_FOUND_ABSENT;
        *reason = strerror(errno);
        return HOOK_FOUND_UNKNOWN;
    }

    /* A link is followed, as the exec follows it: to nothing, there is no hook;
     * to what the invoker cannot reach, the hook is ignored for it */
    if (S_ISLNK(st.st_mode) && stat(path, &st) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) return HOOK_FOUND_ABSENT;
        *reason = strerror(errno);
        return HOOK_FOUND_IGNORED;
    }

    if (!S_ISREG(st.st_mode)) {
        *reason = arena_str_format(
            arena, "it is a %s, not a regular file", fs_stat_noun(&st)
        );
        return HOOK_FOUND_IGNORED;
    }

    /* The mode, in its own words: the exec's for it, "Permission denied", reads
     * as a refusal an identity met — one root would lift — and root lifts no
     * missing +x */
    if (faccessat(AT_FDCWD, path, X_OK, AT_EACCESS) != 0) {
        *reason = errno == EACCES ? "it is not executable" : strerror(errno);
        return HOOK_FOUND_IGNORED;
    }

    return HOOK_FOUND_RUNNABLE;
}

/**
 * The hook's environment, a string array in `arena`: the run's configuration
 * and the process's own environment with its DOTTA_* left out (utils/config.h
 * config_child_env), then the DOTTA_* surface and the command's extras, which
 * nothing the process holds can shadow. An envp as it stands — it always holds
 * DOTTA_DRY_RUN and DOTTA_PATH_COUNT, so its spine exists and is ended.
 */
static void hook_env(
    const config_t *config, const hook_invocation_t *inv, arena_t *arena,
    string_array_t *env
) {
    string_array_init(env, arena, 0);

    /* The run's configuration — the store's directory it settled, the file it
     * read — and the process's environment beneath it */
    config_child_env(config, config->repo_dir, env);

    /* DOTTA_* surface — the command, its profile where it names one, two always-on,
     * then one per path. */
    string_array_pushf(env, "DOTTA_COMMAND=%s", hook_word(inv->cmd));
    if (inv->profile) string_array_pushf(env, "DOTTA_PROFILE=%s", inv->profile);

    string_array_pushf(env, "DOTTA_DRY_RUN=%s", inv->dry_run ? "1" : "0");
    string_array_pushf(env, "DOTTA_PATH_COUNT=%zu", inv->path_count);

    /* Indexed path variables: DOTTA_PATH_0, DOTTA_PATH_1, ... */
    for (size_t i = 0; i < inv->path_count; i++) {
        string_array_pushf(env, "DOTTA_PATH_%zu=%s", i, inv->paths[i]);
    }

    /* Per-command extras (e.g. DOTTA_REMOTE for sync), the surface's own: the
     * process's DOTTA_* never reached the environment, so no stale value of one
     * stands beside it. */
    for (char *const *e = inv->extras; e && *e; e++) string_array_push(env, *e);
}

/**
 * A hook's outcome as its failure, naming the hook: NULL for one that ran to a
 * zero exit
 *
 * The most specific reason first: exec_failed carries the errno of execve, chdir
 * or dup2, so the exit codes 126 and 127 are the script's own, read as any other.
 */
static error_t hook_failure(
    const config_t *config, const char *name, const process_result_t *result
) {
    if (result->exec_failed) {
        return error_create(
            ERR_INTERNAL, "Hook '%s' failed: exec error: %s",
            name, strerror(result->exec_errno)
        );
    }
    if (result->timed_out) {
        return error_create(
            ERR_INTERNAL, "Hook '%s' exceeded timeout of %d seconds",
            name, config->hook_timeout
        );
    }
    if (result->signal_num) {
        return error_create(
            ERR_INTERNAL, "Hook '%s' terminated by signal %d",
            name, result->signal_num
        );
    }
    if (result->exit_code != 0) {
        return error_create(
            ERR_INTERNAL, "Hook '%s' failed with exit code %d",
            name, result->exit_code
        );
    }

    return NULL;
}

/**
 * Fire the invocation's hook of one phase, where its file is executable
 *
 * The file is found as the exec will meet it (hook_find). Absent, nothing runs
 * and nothing is said; what the exec would refuse is ignored with a notice naming
 * why, git's advice (lib/git/hook.c find_hook); and a hooks directory whose names
 * cannot be looked up is said by the pre-fire alone, which every post-fire follows.
 * A runnable hook runs through the unified process primitive under the invocation's
 * environment (hook_env), its outcome its failure (hook_failure). The run's result
 * is the caller's, its stdout/stderr read from the file they went into whatever
 * the outcome, so the caller prints it beside a failure (hook_print_output) and
 * disposes it on every path.
 */
static error_t hook_fire(
    const config_t *config, output_t *out, const hook_invocation_t *inv,
    hook_phase_t phase, process_result_t *out_result
) {
    /* The hook's name, its path and the spawn's environment, in a frame of the
     * call's own: the name and the path read by the lookup below, its notice
     * and the child's exec, the environment by the child at its exec, all dropped
     * with the frame once the hook has run. The directory is the one the
     * configuration settled (utils/config.h). */
    arena_t *frame = arena_create(0);
    const char *hook_name = arena_str_format(
        frame, "%s-%s", phase == HOOK_PHASE_PRE ? "pre" : "post", hook_word(inv->cmd)
    );
    const char *hook_path = str_path_join(frame, config->hooks_dir, hook_name);
    const char *reason = NULL;
    error_t err = NULL;

    /* A hook that will not run is no refusal: its notice is a failed post-hook's
     * register (hook_fire_post), beside a run that goes on */
    switch (hook_find(hook_path, frame, &reason)) {
        case HOOK_FOUND_ABSENT:
            goto cleanup;

        case HOOK_FOUND_UNKNOWN:
            /* Every name in the directory meets it: said once a run, by the
             * pre-fire every post-fire follows */
            if (phase == HOOK_PHASE_PRE) {
                output_warning(
                    out, OUTPUT_NORMAL, "Hooks in '%s' cannot be looked up: %s",
                    config->hooks_dir, reason
                );
            }
            goto cleanup;

        case HOOK_FOUND_IGNORED:
            /* The path named: hooks_dir is the config's to choose, and the name
             * alone is not something a reader can act on */
            output_warning(
                out, OUTPUT_NORMAL, "Hook '%s' at '%s' was ignored: %s",
                hook_name, hook_path, reason
            );
            goto cleanup;

        case HOOK_FOUND_RUNNABLE:
            break;
    }

    /* Sanity check: bound DOTTA_PATH_N env explosion. */
    if (inv->path_count > 10000) {
        err = error_create(
            ERR_INVALID_ARG,
            "Hook '%s': too many paths in context (%zu, limit: 10000)",
            hook_name, inv->path_count
        );
        goto cleanup;
    }

    string_array_t env;
    hook_env(config, inv, frame, &env);

    /* The hook's output goes into a file, read once it exits for the caller to
     * show beside its failure: the wait is on the hook alone, so a task it leaves
     * running holds nothing (sys/process.h PROCESS_OUTPUT_FILE). Under -v it is
     * dotta's own, live as the hook writes it (PROCESS_OUTPUT_INHERIT). */
    char *argv[] = { (char *) hook_path, NULL };  /* execve's type; never written */
    process_spec_t spec = {
        .argv              = argv,
        .envp              = env.entries,
        .stdin_policy      = PROCESS_STDIN_DEVNULL,
        .output_policy     = output_is_verbose(out) ? PROCESS_OUTPUT_INHERIT
                                                    : PROCESS_OUTPUT_FILE,
        .work_dir          = NULL,
        .work_dir_fallback = NULL,
        .timeout_seconds   = config->hook_timeout,
    };

    /* The primitive's own refusals — a pipe, a fork, a wait — name the hook by
     * its path, the program they were handed */
    err = process_run(&spec, out_result);
    if (!err) err = hook_failure(config, hook_name, out_result);

cleanup:
    arena_free(frame);
    return err;
}

/**
 * A failed hook's captured output, at the level its caller's register asks: a
 * refusing pre-hook's is the refusal's reason, read at every level, and a failed
 * post-hook's goes with its warning
 */
static void hook_print_output(
    output_t *out, output_verbosity_t level, const process_result_t *result
) {
    if (result && result->output && result->output_len > 0) {
        /* The hook's bytes are a payload, written as they are — its colours among
         * them, as git passes a hook's output on (base/output.h output_write) */
        output_print(out, level, "Hook output:\n");
        output_write(out, level, OUTPUT_COLOR_RESET, result->output, result->output_len);
        output_endline(out, level);
        /* The capture kept the hook's first bytes (sys/process.h): what it dropped
         * is counted, never shown. */
        if (result->output_dropped > 0) {
            output_print(out, level, "... and %zu more bytes\n", result->output_dropped);
        }
    }
}

error_t hook_fire_pre(
    const config_t *config,
    output_t *out,
    const hook_invocation_t *inv
) {
    CHECK_NULL(config);
    CHECK_NULL(inv);

    /* The refusal names its hook, pre-<command> (hook_fire), so the command says
     * nothing over it */
    process_result_t result = { 0 };
    error_t err = hook_fire(config, out, inv, HOOK_PHASE_PRE, &result);
    if (err) {
        hook_print_output(out, OUTPUT_QUIET, &result);
    }
    process_result_deinit(&result);
    return err;
}

void hook_fire_post(
    const config_t *config,
    output_t *out,
    const hook_invocation_t *inv
) {
    CHECK_NULL(config);
    CHECK_NULL(inv);

    if (inv->dry_run) return;

    /* A failure the run goes past, warned in its own words: they name the hook,
     * post-<command> (hook_fire) */
    process_result_t result = { 0 };
    error_t err = hook_fire(config, out, inv, HOOK_PHASE_POST, &result);
    if (err) {
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
        hook_print_output(out, OUTPUT_NORMAL, &result);
    }
    process_result_deinit(&result);
}
