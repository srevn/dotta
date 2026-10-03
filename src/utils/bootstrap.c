/**
 * bootstrap.c - Profile bootstrap orchestration
 *
 * See utils/bootstrap.h for the contract. Structured in three bands:
 *   1. Environment construction (DOTTA_* + filtered parent env).
 *   2. Single-profile execution (extract + exec OR in-memory validate).
 *   3. Public orchestrator (iterate, account in the receipt).
 *
 * This file owns every command-scoped concern of bootstrap: env, timeout, working
 * directory, process-group policy, progress output, and the receipt. The
 * sys/bootstrap primitives know none of this and cannot reach back up across
 * the layer boundary.
 */

#include "utils/bootstrap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "sys/bootstrap.h"
#include "sys/identity.h"
#include "sys/process.h"

/* Per-script timeout. Bootstrap scripts may install packages, compile software,
 * or download large artefacts; 10 minutes is generous without being unbounded. */
#define BOOTSTRAP_TIMEOUT_SECONDS 600

/**
 * The DOTTA_* environment for a live bootstrap script, layered on top of a filtered
 * copy of the parent's environment (DOTTA_* stripped to prevent shadowing), as
 * a string array in `arena`: an envp as it stands.
 */
static void bootstrap_env(
    const char *repo_dir,
    const char *profile,
    const char *all_profiles,
    arena_t *arena,
    string_array_t *env
) {
    extern char **environ;

    string_array_init(env, arena);

    /* DOTTA_DRY_RUN is the live path's: a dry run spawns nothing */
    string_array_pushf(env, "DOTTA_REPO_DIR=%s", repo_dir);
    string_array_pushf(env, "DOTTA_PROFILE=%s", profile);
    string_array_pushf(env, "DOTTA_PROFILES=%s", all_profiles);
    string_array_push(env, "DOTTA_DRY_RUN=0");

    /* Passthrough parent env, skipping DOTTA_* to preserve the invariant that
     * our four variables are the authoritative DOTTA_* surface visible to the
     * child. */
    for (char **e = environ; *e; e++) {
        if (str_starts_with(*e, "DOTTA_")) continue;
        string_array_push(env, *e);
    }
}

/**
 * Map a process_result_t into a domain-specific error.
 *
 * Returns NULL iff the script ran to completion with exit code 0. Otherwise,
 * composes a short message keyed to the most specific reason available —
 * exec_failed takes precedence (child-side errno captures "bad shebang" / "ENOENT
 * interpreter"), then timeout, then signal, then non-zero exit.
 */
static error_t script_error(const process_result_t *r) {
    if (r->exec_failed) {
        return error_create(
            ERR_INTERNAL, "exec failed: %s", strerror(r->exec_errno)
        );
    }
    if (r->timed_out) {
        return error_create(
            ERR_INTERNAL, "timed out after %d seconds",
            BOOTSTRAP_TIMEOUT_SECONDS
        );
    }
    if (r->signal_num) {
        return error_create(
            ERR_INTERNAL, "terminated by signal %d", r->signal_num
        );
    }
    if (r->exit_code != 0) {
        return error_create(
            ERR_INTERNAL, "exited with code %d", r->exit_code
        );
    }
    return NULL;
}

/**
 * Execute one profile's bootstrap script.
 *
 * Extracts to a secure temp file, builds the environment, execs via sys/process
 * in PROCESS_PGRP_SHARED so terminal Ctrl+C reaches the child, then unlinks the
 * temp file unconditionally. The extracted file exists only between
 * bootstrap_extract_to_temp and the exec — the window is tight by design.
 */
static error_t run_live(
    git_repository *repo,
    const char *profile,
    const char *repo_dir,
    const char *all_profiles
) {
    char *temp_path = NULL;
    arena_t *frame = NULL;
    process_result_t result = { 0 };

    error_t err = bootstrap_extract_to_temp(repo, profile, &temp_path);
    if (err) {
        err = error_wrap(err, "Failed to extract bootstrap script");
        goto cleanup;
    }

    /* The script's environment, in a frame of the spawn's own: read by the child
     * at its exec, and dropped with the frame once the script has run */
    frame = arena_create(0);
    string_array_t env;
    bootstrap_env(repo_dir, profile, all_profiles, frame, &env);

    /* Run the script from the invoker's HOME (sys/identity — under sudo the user's,
     * not /root) so it behaves like a normal interactive shell session: relative
     * paths in the script resolve under $HOME. The spec carries `repo_dir` as
     * the fallback for a home the child cannot enter. */
    char *argv[] = { temp_path, NULL };
    process_spec_t spec = {
        .argv              = argv,
        .envp              = env.entries,
        .stdin_policy      = PROCESS_STDIN_INHERIT,
        .capture           = false,
        .stream_fd         = STDOUT_FILENO,
        .work_dir          = identity()->home,
        .work_dir_fallback = repo_dir,
        .timeout_seconds   = BOOTSTRAP_TIMEOUT_SECONDS,
        .pgrp_policy       = PROCESS_PGRP_SHARED,
    };

    err = process_run(&spec, &result);
    if (err) goto cleanup;

    err = script_error(&result);

cleanup:
    process_result_deinit(&result);
    arena_free(frame);
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    return err;
}

/**
 * Dry-run: read the script into memory, validate its shebang, free. No temp file,
 * no subprocess, no environment build.
 */
static error_t run_dry(git_repository *repo, const char *profile) {
    buffer_t content = BUFFER_INIT;
    error_t err = bootstrap_read(repo, profile, &content);
    if (err) {
        buffer_deinit(&content);
        return err;
    }

    err = bootstrap_validate(
        (const unsigned char *) content.data, content.size
    );
    buffer_deinit(&content);
    return err;
}

bootstrap_receipt_t bootstrap_fire(output_t *out, const bootstrap_spec_t *spec) {
    CHECK_NULL(out);
    CHECK_NULL(spec);
    CHECK_NULL(spec->repo);
    CHECK_NULL(spec->repo_dir);
    CHECK_NULL(spec->profiles);

    /* Bootstrap script output is streamed directly to STDOUT_FILENO (bypassing
     * `out`), so the orchestrator's progress lines and the child's output
     * interleave correctly only when `out` routes to stdout. Guard the invariant
     * loudly. */
    CHECK_ARG(out->stream == stdout, "out must route to stdout");

    /* The profiles are the caller's listing: every one has a script, which the
     * caller asked of each (bootstrap_exists) before it showed them and asked
     * to run them. DOTTA_PROFILES exposes that set to each child — the scripts
     * being run, not every profile the user named — matching the "[N/M]" progress
     * numbering, so no script is misled about peers that are not participating. */
    const string_array_t *profiles = spec->profiles;

    /* The run's own lists — the names joined for DOTTA_PROFILES, and the failed
     * profiles' for the end-of-run summary — in a frame of the run's own, freed
     * at its one exit */
    arena_t *frame = arena_create(0);
    const char *all_profiles = string_array_join(frame, profiles, " ");
    string_array_t failed;
    string_array_init(&failed, frame);
    bootstrap_receipt_t receipt = { 0 };

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->entries[i];

        output_print(
            out, OUTPUT_NORMAL, "[%zu/%zu] Running %s/%s...\n",
            i + 1, profiles->count, profile, BOOTSTRAP_SCRIPT_NAME
        );

        /* Flush the progress line so it lands on stdout before the child begins
         * writing. Without this, redirected/piped stdout can interleave the child's
         * raw writes ahead of our stdio-buffered line. */
        fflush(out->stream);

        error_t step_err = spec->dry_run
            ? run_dry(spec->repo, profile)
            : run_live(
            spec->repo, profile, spec->repo_dir, all_profiles
            );

        if (!step_err) {
            output_print(
                out, OUTPUT_NORMAL, "  {green}✓{reset} %s\n",
                spec->dry_run ? "Would execute" : "Complete"
            );
            continue;
        }

        /* The failure names its script: a row the caller's refusal counts prints
         * at every level, where the progress line above it is the report's
         * (base/output.h OUTPUT_QUIET) */
        output_print(
            out, OUTPUT_QUIET, "  {red}✗{reset} %s/%s: %s\n",
            profile, BOOTSTRAP_SCRIPT_NAME, error_line(step_err)
        );

        /* The failure, named for the receipt and the summary. The step's error
         * is dropped, its details already on the row — one per failed script. */
        string_array_push(&failed, profile);

        /* A stop ends the run here, and the receipt says where: the cause is
         * the row's, so nothing restates it. The name is the caller's own
         * string. */
        if (spec->stop_on_error) {
            receipt.stopped = profile;
            break;
        }
    }
    receipt.failures = failed.count;

    /* The summary, of a run that went on past its failures: the failed scripts
     * named again in one place, since their rows stand among whatever the scripts
     * wrote — the "Found" section's rows, failed. No count: its one home is the
     * caller's refusal. A stop's one failure is its answer already, named where
     * it stopped. */
    if (receipt.failures > 0 && receipt.stopped == NULL) {
        output_section(out, OUTPUT_NORMAL, "Failed bootstrap scripts");
        for (size_t i = 0; i < failed.count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s/%s\n",
                failed.entries[i], BOOTSTRAP_SCRIPT_NAME
            );
        }
    }

    arena_free(frame);
    return receipt;
}
