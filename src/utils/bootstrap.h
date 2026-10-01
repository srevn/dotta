/**
 * bootstrap.h - Profile bootstrap orchestration
 *
 * Runs per-profile .bootstrap scripts in order, with progress reporting, dry-run
 * validation, and a receipt of what the run did.
 *
 * This is the command-scoped orchestrator sitting on top of the content primitives
 * in sys/bootstrap.h and the unified subprocess primitive in sys/process.h. Its
 * public surface is a single function — bootstrap_fire — plus the two value types
 * it reads and answers: one invocation, and its receipt. Mirrors the shape of
 * utils/hooks.h.
 */

#ifndef DOTTA_UTILS_BOOTSTRAP_H
#define DOTTA_UTILS_BOOTSTRAP_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

/**
 * Bootstrap invocation specification.
 *
 * Value type — callers stack-allocate and populate via designated initializers.
 * All pointer fields are borrowed; callers must keep the underlying storage valid
 * for the duration of bootstrap_fire().
 *
 * Fields:
 *   repo           Open Git repository.
 *   repo_dir       Absolute path to the repository. Becomes
 *                  DOTTA_REPO_DIR for each spawned script. May differ from
 *                  config->repo_dir — `dotta clone <url> <path>` bootstraps the
 *                  store it made at <path>, wherever the configuration looks.
 *   profiles       The profiles whose scripts run, in execution order: the
 *                  caller's listing, every one of which has a .bootstrap script
 *                  (sys/bootstrap.h bootstrap_exists) — the set the caller showed
 *                  before asking to run it.
 *   dry_run        True: validate each script's shebang in memory
 *                  and report "would execute". No /tmp write, no process spawn,
 *                  no side effects.
 *   stop_on_error  True: stop at the first failure, the receipt naming the
 *                  profile it stopped at. False: continue through the remaining
 *                  profiles, the receipt counting the failures.
 */
typedef struct {
    git_repository *repo;
    const char *repo_dir;
    const string_array_t *profiles;
    bool dry_run;
    bool stop_on_error;
} bootstrap_spec_t;

/**
 * What a run of the scripts did
 *
 * A value, complete: every way a run fails is one script's, said on its row with
 * its cause as the run goes, so bootstrap_fire has no failure of its own and
 * its callers read their fate off this (cmds/bootstrap.c cmd_bootstrap,
 * cmds/clone.c cmd_clone).
 */
typedef struct {
    size_t failures;        /* Scripts that failed — their validation, under dry_run */
    const char *stopped;    /* The profile a stop ended the run at (spec's); NULL: none */
} bootstrap_receipt_t;

/**
 * Run the .bootstrap script of each profile in spec->profiles, in order.
 *
 * Behavior:
 *   - Progress: "[N/M] Running profile/.bootstrap..." is emitted via `out` before
 *     each script; "✓ Complete" (or "Would execute" in dry-run) on success; "✗
 *     Failed: <reason>" on error.
 *   - Dry-run: reads each script's content and validates its shebang in memory.
 *     No /tmp writes, no process spawns.
 *   - Live run: extracts the script to a tight-scoped temp file and execs it
 *     under sys/process with these settings:
 *       - Environment: DOTTA_REPO_DIR, DOTTA_PROFILE, DOTTA_PROFILES
 *         (space-separated list of scripts being run), DOTTA_DRY_RUN (always
 *         "0" on the live path). Parent env passes through with DOTTA_* stripped
 *         to avoid shadowing.
 *       - Working directory: $HOME if set, else spec->repo_dir.
 *       - Stdin: inherited (scripts may prompt the user).
 *       - Process group: SHARED — terminal Ctrl+C reaches both dotta and the
 *         child, which is the correct behavior for interactive bootstrap work.
 *       - Timeout: 600 seconds per script.
 *
 * Returns the receipt, and never an error: a script that fails — its exec, its
 * exit, its timeout, its extraction, its validation under dry_run — is said on
 * its row with its cause, and counted.
 *   - spec->stop_on_error=true: the run stops at the first failure, the scripts
 *     after it never run, and the receipt names the profile it stopped at.
 *   - spec->stop_on_error=false: every script runs, and a run that met failures
 *     closes with a summary naming them (output_warning).
 *
 * Preconditions:
 *   - spec->repo, spec->repo_dir, spec->profiles are non-NULL.
 *   - out != NULL AND out->stream == stdout. A contract check defends the second
 *     invariant: bootstrap script output bypasses `out` and writes directly to
 *     STDOUT_FILENO, so interleaving is correct only when `out` also routes to
 *     stdout.
 */
bootstrap_receipt_t bootstrap_fire(
    output_t *out,
    const bootstrap_spec_t *spec
);

#endif /* DOTTA_UTILS_BOOTSTRAP_H */
