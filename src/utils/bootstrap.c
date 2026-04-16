/**
 * bootstrap.c - Profile bootstrap orchestration
 *
 * See utils/bootstrap.h for the contract. Structured in three bands:
 *   1. Environment construction (DOTTA_* + filtered parent env).
 *   2. Single-profile execution (extract + exec OR in-memory validate).
 *   3. Public orchestrator (filter, iterate, aggregate).
 *
 * This file owns every command-scoped concern of bootstrap: env,
 * timeout, working directory, process-group policy, progress output,
 * and failure aggregation. The sys/bootstrap primitives know none of
 * this and cannot reach back up across the layer boundary.
 */

#include "utils/bootstrap.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "sys/bootstrap.h"
#include "sys/process.h"

/* Per-script timeout. Bootstrap scripts may install packages, compile
 * software, or download large artefacts; 10 minutes is generous
 * without being unbounded. */
#define BOOTSTRAP_TIMEOUT_SECONDS 600

/**
 * Free a NULL-terminated environment array of `count` heap strings.
 * No-op on NULL input; callers can free unconditionally.
 */
static void env_free(char **env, size_t count) {
    if (!env) return;
    for (size_t i = 0; i < count; i++) free(env[i]);
    free(env);
}

/**
 * Build the DOTTA_* environment for a bootstrap script, layered on
 * top of a filtered copy of the parent's environment (DOTTA_*
 * stripped to prevent shadowing).
 *
 * Returns a NULL-terminated `char **` suitable for execve, or NULL
 * on allocation failure. On success, *out_count is the number of
 * non-NULL entries; the caller frees via env_free().
 *
 * All string inputs are required to be non-NULL — the helper is
 * static and has a single caller that validates upstream.
 */
static char **env_build(
    const char *repo_dir,
    const char *profile,
    const char *all_profiles,
    bool dry_run,
    size_t *out_count
) {
    extern char **environ;
    *out_count = 0;

    /* Count passthrough parent-env entries so we can allocate once. */
    size_t parent_count = 0;
    for (char **e = environ; *e; e++) {
        if (!str_starts_with(*e, "DOTTA_")) parent_count++;
    }

    /* 4 DOTTA_* entries + parent entries + 1 NULL terminator. */
    const size_t dotta_vars = 4;
    size_t cap = dotta_vars + parent_count + 1;
    char **env = calloc(cap, sizeof(char *));
    if (!env) return NULL;

    size_t n = 0;

    env[n] = str_format("DOTTA_REPO_DIR=%s", repo_dir);
    if (!env[n]) goto cleanup;
    n++;

    env[n] = str_format("DOTTA_PROFILE=%s", profile);
    if (!env[n]) goto cleanup;
    n++;

    env[n] = str_format("DOTTA_PROFILES=%s", all_profiles);
    if (!env[n]) goto cleanup;
    n++;

    env[n] = str_format("DOTTA_DRY_RUN=%s", dry_run ? "1" : "0");
    if (!env[n]) goto cleanup;
    n++;

    /* Passthrough parent env, skipping DOTTA_* to preserve the
     * invariant that our four variables are the authoritative
     * DOTTA_* surface visible to the child. */
    for (char **e = environ; *e; e++) {
        if (str_starts_with(*e, "DOTTA_")) continue;
        env[n] = strdup(*e);
        if (!env[n]) goto cleanup;
        n++;
    }

    env[n] = NULL;
    *out_count = n;
    return env;

cleanup:
    env_free(env, n);
    return NULL;
}

/**
 * Map a process_result_t into a domain-specific error.
 *
 * Returns NULL iff the script ran to completion with exit code 0.
 * Otherwise, composes a short message keyed to the most specific
 * reason available — exec_failed takes precedence (child-side errno
 * captures "bad shebang" / "ENOENT interpreter"), then timeout,
 * then signal, then non-zero exit.
 */
static error_t *script_error(const process_result_t *r) {
    if (r->exec_failed) {
        return ERROR(
            ERR_INTERNAL, "exec failed: %s", strerror(r->exec_errno)
        );
    }
    if (r->timed_out) {
        return ERROR(
            ERR_INTERNAL, "timed out after %d seconds",
            BOOTSTRAP_TIMEOUT_SECONDS
        );
    }
    if (r->signal_num) {
        return ERROR(
            ERR_INTERNAL, "terminated by signal %d", r->signal_num
        );
    }
    if (r->exit_code != 0) {
        return ERROR(
            ERR_INTERNAL, "exited with code %d", r->exit_code
        );
    }
    return NULL;
}

/**
 * Execute one profile's bootstrap script.
 *
 * Extracts to a secure temp file, builds the environment, execs via
 * sys/process in PROCESS_PGRP_SHARED so terminal Ctrl+C reaches the
 * child, then unlinks the temp file unconditionally. The extracted
 * file exists only between bootstrap_extract_to_temp and the exec —
 * the window is tight by design.
 */
static error_t *run_live(
    git_repository *repo,
    const char *profile,
    const char *repo_dir,
    const char *all_profiles
) {
    char *temp_path = NULL;
    char **env = NULL;
    size_t env_count = 0;
    process_result_t result = { 0 };
    error_t *err = NULL;

    err = bootstrap_extract_to_temp(repo, profile, &temp_path);
    if (err) {
        err = error_wrap(err, "Failed to extract bootstrap script");
        goto cleanup;
    }

    env = env_build(
        repo_dir, profile, all_profiles, /*dry_run=*/ false, &env_count
    );
    if (!env) {
        err = ERROR(ERR_MEMORY, "Failed to build bootstrap environment");
        goto cleanup;
    }

    char *argv[] = { temp_path, NULL };
    process_spec_t spec = {
        .argv              = argv,
        .envp              = env,
        .stdin_policy      = PROCESS_STDIN_INHERIT,
        .capture           = false,
        .stream_fd         = STDOUT_FILENO,
        .work_dir          = getenv("HOME"),
        .work_dir_fallback = repo_dir,
        .timeout_seconds   = BOOTSTRAP_TIMEOUT_SECONDS,
        .pgrp_policy       = PROCESS_PGRP_SHARED,
    };

    err = process_run(&spec, &result);
    if (err) goto cleanup;

    err = script_error(&result);

cleanup:
    process_result_dispose(&result);
    env_free(env, env_count);
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    return err;
}

/**
 * Dry-run: read the script into memory, validate its shebang, free.
 * No temp file, no subprocess, no environment build.
 */
static error_t *run_dry(git_repository *repo, const char *profile) {
    buffer_t content = BUFFER_INIT;
    error_t *err = bootstrap_read(repo, profile, &content);
    if (err) {
        buffer_free(&content);
        return err;
    }

    err = bootstrap_validate(
        (const unsigned char *) content.data, content.size
    );
    buffer_free(&content);
    return err;
}

error_t *bootstrap_fire(output_ctx_t *out, const bootstrap_spec_t *spec) {
    CHECK_NULL(out);
    CHECK_NULL(spec);
    CHECK_NULL(spec->repo);
    CHECK_NULL(spec->repo_dir);
    CHECK_NULL(spec->profiles);

    /* Bootstrap script output is streamed directly to STDOUT_FILENO
     * (bypassing `out`), so the orchestrator's progress lines and
     * the child's output interleave correctly only when `out`
     * routes to stdout. Guard the invariant loudly. */
    assert(out->stream == stdout);

    error_t *err = NULL;

    /* Single-pass filter: keep only profiles that have a script, in
     * order. STRING_ARRAY_AUTO ensures the list is freed on every
     * exit path. */
    string_array_t found STRING_ARRAY_AUTO = { 0 };
    for (size_t i = 0; i < spec->profiles->count; i++) {
        const char *p = spec->profiles->items[i];
        if (bootstrap_exists(spec->repo, p)) {
            err = string_array_push(&found, p);
            if (err) return error_wrap(err, "Failed to collect profiles");
        }
    }

    if (found.count == 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "No bootstrap scripts found in the given profiles."
        );
        return NULL;
    }

    /* DOTTA_PROFILES exposes the set of scripts being run to each
     * child — not the set of profiles the user passed in. This
     * matches the "[N/M]" progress numbering and avoids misleading
     * scripts about peers that aren't participating. */
    char *all_profiles = string_array_join(&found, " ");
    if (!all_profiles) {
        return ERROR(ERR_MEMORY, "Failed to join profile names");
    }

    /* Failure tracking: fail_count is authoritative (advances even
     * if recording the profile name OOMs); `failed` holds the names
     * we successfully recorded for the end-of-run summary. */
    string_array_t failed STRING_ARRAY_AUTO = { 0 };
    size_t fail_count = 0;

    for (size_t i = 0; i < found.count; i++) {
        const char *profile = found.items[i];

        output_print(
            out, OUTPUT_NORMAL, "[%zu/%zu] Running %s/%s...\n",
            i + 1, found.count, profile, BOOTSTRAP_SCRIPT_NAME
        );

        /* Flush the progress line so it lands on stdout before the
         * child begins writing. Without this, redirected/piped
         * stdout can interleave the child's raw writes ahead of our
         * stdio-buffered line. */
        fflush(out->stream);

        error_t *step_err = spec->dry_run
            ? run_dry(spec->repo, profile)
            : run_live(
            spec->repo, profile, spec->repo_dir, all_profiles
            );

        if (!step_err) {
            output_styled(
                out, OUTPUT_NORMAL, "  {green}✓{reset} %s\n",
                spec->dry_run ? "Would execute" : "Complete"
            );
            continue;
        }

        output_styled(
            out, OUTPUT_NORMAL, "  {red}✗{reset} %s: %s\n",
            spec->dry_run ? "Validation failed" : "Failed",
            error_message(step_err)
        );

        if (spec->stop_on_error) {
            free(all_profiles);
            return error_wrap(
                step_err, "Bootstrap failed for profile '%s'", profile
            );
        }

        /* Continue-on-error: remember for the summary, then free the
         * per-step error (the details are already on screen). An
         * OOM while pushing the profile name is not fatal — we still
         * advance fail_count so the final summary is accurate. */
        fail_count++;
        error_t *push_err = string_array_push(&failed, profile);
        if (push_err) error_free(push_err);
        error_free(step_err);
    }

    free(all_profiles);

    if (fail_count == 0) return NULL;

    output_newline(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL, "%zu bootstrap script%s failed:",
        fail_count, fail_count == 1 ? "" : "s"
    );
    for (size_t i = 0; i < failed.count; i++) {
        output_print(out, OUTPUT_NORMAL, "  - %s\n", failed.items[i]);
    }

    return ERROR(
        ERR_INTERNAL, "%zu of %zu bootstrap script%s failed",
        fail_count, found.count, fail_count == 1 ? "" : "s"
    );
}
