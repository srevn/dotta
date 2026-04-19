/**
 * bootstrap.h - Profile bootstrap orchestration
 *
 * Runs per-profile .bootstrap scripts in order, with progress
 * reporting, dry-run validation, and aggregated failure handling.
 *
 * This is the command-scoped orchestrator sitting on top of the
 * content primitives in sys/bootstrap.h and the unified subprocess
 * primitive in sys/process.h. Its public surface is a single
 * function — bootstrap_fire — plus the value type used to describe
 * one invocation. Mirrors the shape of utils/hooks.h.
 */

#ifndef DOTTA_UTILS_BOOTSTRAP_H
#define DOTTA_UTILS_BOOTSTRAP_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

/**
 * Bootstrap invocation specification.
 *
 * Value type — callers stack-allocate and populate via designated
 * initializers. All pointer fields are borrowed; callers must keep
 * the underlying storage valid for the duration of bootstrap_fire().
 *
 * Fields:
 *   repo           Open Git repository.
 *   repo_dir       Absolute path to the repository. Becomes
 *                  DOTTA_REPO_DIR for each spawned script. May
 *                  differ from the default repo location — e.g.,
 *                  `dotta clone --path <dir>` honors an override
 *                  that does not match config->repo_dir.
 *   profiles       Profiles to consider, in execution order.
 *                  Profiles without a .bootstrap script are silently
 *                  skipped after a single existence pass.
 *   dry_run        True: validate each script's shebang in memory
 *                  and report "would execute". No /tmp write, no
 *                  process spawn, no side effects.
 *   stop_on_error  True: abort on the first failure with a wrapped
 *                  error naming the profile. False: continue through
 *                  the remaining profiles; at the end, return an
 *                  aggregated error if any failed.
 */
typedef struct {
    git_repository *repo;
    const char *repo_dir;
    const string_array_t *profiles;
    bool dry_run;
    bool stop_on_error;
} bootstrap_spec_t;

/**
 * Run .bootstrap scripts for each profile in spec->profiles that
 * has one.
 *
 * Behavior:
 *   - Single-pass filter: profiles are checked once for .bootstrap
 *     existence; only those with a script are iterated. N/M progress
 *     is computed from the filtered count.
 *   - Progress: "[N/M] Running profile/.bootstrap..." is emitted via
 *     `out` before each script; "✓ Complete" (or "Would execute" in
 *     dry-run) on success; "✗ Failed: <reason>" on error.
 *   - Dry-run: reads each script's content and validates its shebang
 *     in memory. No /tmp writes, no process spawns.
 *   - Live run: extracts the script to a tight-scoped temp file and
 *     execs it under sys/process with these settings:
 *       - Environment: DOTTA_REPO_DIR, DOTTA_PROFILE, DOTTA_PROFILES
 *         (space-separated list of scripts being run), DOTTA_DRY_RUN
 *         (always "0" on the live path). Parent env passes through
 *         with DOTTA_* stripped to avoid shadowing.
 *       - Working directory: $HOME if set, else spec->repo_dir.
 *       - Stdin: inherited (scripts may prompt the user).
 *       - Process group: SHARED — terminal Ctrl+C reaches both
 *         dotta and the child, which is the correct behavior for
 *         interactive bootstrap work.
 *       - Timeout: 600 seconds per script.
 *
 * Returns:
 *   - NULL if no profile had a .bootstrap script OR if every script
 *     succeeded (or validated, for dry-run).
 *   - On spec->stop_on_error=true: the first failure is returned,
 *     wrapped with the failing profile name.
 *   - On spec->stop_on_error=false: after iterating every profile,
 *     an ERR_INTERNAL summary error is returned with the failure
 *     count. The list of failed profiles is printed via
 *     output_warning before return, so the caller can swallow the
 *     error without losing user-visible context.
 *
 * Preconditions:
 *   - spec->repo, spec->repo_dir, spec->profiles are non-NULL.
 *   - out != NULL AND out->stream == stdout. A debug assert defends
 *     the second invariant: bootstrap script output bypasses `out`
 *     and writes directly to STDOUT_FILENO, so interleaving is
 *     correct only when `out` also routes to stdout.
 */
error_t *bootstrap_fire(
    output_t *out,
    const bootstrap_spec_t *spec
);

#endif /* DOTTA_UTILS_BOOTSTRAP_H */
