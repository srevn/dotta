/**
 * main.c - Dotta entry point
 *
 * Dotfile manager using git branches as profiles.
 */

#include <git2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "cmds/add.h"
#include "cmds/apply.h"
#include "cmds/bootstrap.h"
#include "cmds/clone.h"
#include "cmds/completion.h"
#include "cmds/diff.h"
#include "cmds/git.h"
#include "cmds/ignore.h"
#include "cmds/init.h"
#include "cmds/interactive.h"
#include "cmds/key.h"
#include "cmds/list.h"
#include "cmds/profile.h"
#include "cmds/remote.h"
#include "cmds/remove.h"
#include "cmds/revert.h"
#include "cmds/runtime.h"
#include "cmds/show.h"
#include "cmds/status.h"
#include "cmds/sync.h"
#include "cmds/update.h"
#include "crypto/encryption.h"
#include "crypto/keymgr.h"
#include "utils/config.h"
#include "utils/privilege.h"
#include "utils/repo.h"
#include "utils/version.h"

/**
 * Root command registry — every user-facing top-level command.
 *
 * The single place that names every command the CLI exposes. Two
 * consumers project this array into behavior:
 *
 *   - `args_resolve_root` / `args_render_root_usage` — direct calls
 *     from main, resolving argv[1] and rendering top-level help;
 *   - the fish completion exporter in `cmds/completion.c` — receives
 *     the array as `dotta_ctx_t::commands` (one of the fields below)
 *     so the cmds layer never imports the registry symbol.
 *
 * Ordered for root-help readability: setup → file ops → deploy/undo →
 * inspect → remote → profile/remote mgmt → config → passthrough →
 * special. Every projection (dispatch, help, fish export) walks this
 * array, so the order is the display order everywhere. NULL-terminated
 * for `for (size_t i = 0; reg[i] != NULL; i++)` loops.
 */
static const args_command_t *const dotta_commands[] = {
    &spec_init,        &spec_clone,      &spec_add,
    &spec_remove,      &spec_update,     &spec_apply,
    &spec_revert,      &spec_status,     &spec_diff,
    &spec_list,        &spec_show,       &spec_sync,
    &spec_profile,     &spec_remote,     &spec_ignore,
    &spec_bootstrap,   &spec_key,        &spec_git,
    &spec_interactive, &spec_completion, NULL
};

/**
 * Open a repository handle according to the command's declared mode.
 *
 * Returns 0 on success, 1 on unrecoverable error (error is printed).
 * On success, `*repo_out` and `*path_out` are set per mode:
 *
 *   DOTTA_REPO_NONE            → both NULL
 *   DOTTA_REPO_REQUIRED        → repo set, path NULL
 *   DOTTA_REPO_OPTIONAL_SILENT → repo maybe NULL, path NULL, no errors
 *   DOTTA_REPO_PATH_ONLY       → repo NULL (released), path set
 */
static int open_repo_for_mode(
    dotta_repo_mode_t mode,
    const config_t *config,
    git_repository **repo_out,
    char **path_out
) {
    *repo_out = NULL;
    *path_out = NULL;

    switch (mode) {
        case DOTTA_REPO_NONE:
            return 0;

        case DOTTA_REPO_REQUIRED: {
            error_t *err = repo_open(config, repo_out, NULL);
            if (err != NULL) {
                error_print(err, stderr);
                error_free(err);
                return 1;
            }
            return 0;
        }

        case DOTTA_REPO_OPTIONAL_SILENT: {
            error_t *err = repo_open(config, repo_out, NULL);
            if (err != NULL) {
                error_free(err);
                *repo_out = NULL;
            }
            return 0;
        }

        case DOTTA_REPO_PATH_ONLY: {
            git_repository *repo = NULL;
            error_t *err = repo_open(config, &repo, path_out);
            if (err != NULL) {
                error_print(err, stderr);
                error_free(err);
                return 1;
            }
            /* Consumers want the path, not the handle (e.g. `git`
             * passthrough forks a child with `--git-dir=<path>`). */
            git_repository_free(repo);
            return 0;
        }
    }
    return 0;
}

/**
 * Parse, dispatch, and cleanup for one spec-engine command.
 *
 * Owns a command-scoped arena (destroyed before return). Follows the
 * outcome → render → dispatch → teardown sequence. Never calls exit();
 * the caller's cleanup chain is preserved unchanged.
 */
static int run_spec(
    const args_command_t *cmd,
    int argc, char **argv,
    const config_t *config,
    output_ctx_t *out
) {
    const char *prog = argv[0];

    arena_t *arena = arena_create(8 * 1024);
    if (arena == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    /* `resolved` tracks the leaf command after subcommand resolution.
     * For a flat command this stays equal to `cmd`; for a tree it is
     * the matched child (so help and errors render against the actual
     * subcommand the user typed, and dispatch goes to its handler). */
    const args_command_t *resolved = cmd;

    /* Passthrough commands (e.g. `git`) skip parsing but still honor
     * repo_mode, so PATH_ONLY passthrough can resolve the repo path
     * without a second `repo_open` inside dispatch. */
    void *opts = NULL;
    if (!cmd->passthrough) {
        if (cmd->opts_size > 0) {
            opts = arena_calloc(arena, 1, cmd->opts_size);
            if (opts == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                arena_destroy(arena);
                return 1;
            }
        }

        /* Parse. The engine resets `errors` in-place, so the uninitialized
         * stack declaration is intentional. */
        args_errors_t errors;
        args_outcome_t outcome = args_parse(
            cmd, argc, argv, 2, arena, opts, &errors, &resolved
        );

        switch (outcome) {
            case ARGS_HELP_REQUESTED:
                args_render_help(stdout, resolved, prog);
                arena_destroy(arena);
                return 0;
            case ARGS_FAILED:
                if (!resolved->silent_failure) {
                    args_render_errors(stderr, &errors, resolved, prog);
                }
                arena_destroy(arena);
                return 1;
            case ARGS_OK:
                break;
        }
    }

    /* Each command's spec stashes its repo-open contract in `user_data`
     * via a `dotta_spec_ext_t` constant. NULL falls back to NONE so a
     * spec that omits user_data simply gets no repo (safe default). */
    const dotta_spec_ext_t *ext = resolved->user_data;
    dotta_repo_mode_t mode = ext != NULL ? ext->repo_mode : DOTTA_REPO_NONE;

    git_repository *repo = NULL;
    char *repo_path = NULL;
    if (open_repo_for_mode(mode, config, &repo, &repo_path) != 0) {
        arena_destroy(arena);
        return 1;
    }

    int exit_override = 0;
    dotta_ctx_t ctx = {
        .repo      = repo,
        .repo_path = repo_path,
        .config    = config,
        .out       = out,
        .arena     = arena,
        .argc      = argc,
        .argv      = argv,
        .exit_code = &exit_override,
        .commands  = dotta_commands,
    };

    error_t *err = resolved->dispatch(&ctx, opts);

    if (repo != NULL) git_repository_free(repo);
    free(repo_path);
    arena_destroy(arena);

    if (err != NULL) {
        if (!resolved->silent_failure) error_print(err, stderr);
        error_free(err);
        return 1;
    }
    /* Passthrough dispatch writes via *ctx->exit_code to propagate the
     * child's exact status (0, 1, 2, 128+n). Native commands leave it at 0. */
    return exit_override;
}

/* Published by sys/process.c::process_run() while a PROCESS_PGRP_NEW
 * child is alive; zero otherwise. The signal handler reads it to
 * forward terminating signals to the child's process group before
 * dotta dies, so a Ctrl+C kills both atomically rather than
 * orphaning the spawned hook.
 *
 * PROCESS_PGRP_SHARED children leave this at zero — the kernel
 * already delivers terminal SIGINT/SIGTERM to the entire foreground
 * group, so parent and child receive it without forwarding.
 *
 * volatile sig_atomic_t is required for async-signal-safe access
 * from the handler (POSIX). */
volatile sig_atomic_t active_child_pgid = 0;

/**
 * Signal handler for cleanup on SIGINT/SIGTERM
 *
 * Ensures that the global keymgr is properly cleaned up (master key
 * zeroed in memory) when the user interrupts the program with Ctrl+C
 * or when the process receives a termination signal.
 *
 * Cleanup Architecture:
 * - Child propagation: If a PROCESS_PGRP_NEW child (e.g. a hook) is
 *   alive, forward the signal to its process group BEFORE local
 *   cleanup so the child dies atomically with dotta. SHARED children
 *   get no forwarding — the kernel routes their copy via the
 *   foreground process group directly.
 * - Keymanager: Cleaned here (security-critical, global state)
 * - Worktrees: Self-healing on next invocation
 * - Temp files: Minor impact, OS cleans eventually
 * - Transactions: Auto-rollback by SQLite (WAL mode)
 *
 * Rationale: Signal handlers are heavily restricted (async-signal-safety).
 * We cannot safely clean worktrees here (requires malloc/free via libgit2).
 * Instead, worktree.c implements transparent orphan cleanup on next run,
 * which is more robust and handles all failure modes (Ctrl-C, crashes, kill -9).
 *
 * AS-safety: kill(2), signal(), and raise() are AS-safe per POSIX
 * SUSv4 §2.4.3; reading volatile sig_atomic_t is atomic by definition.
 */
static void signal_cleanup_handler(int signum) {
    /* Forward first, so the child group starts dying even if local
     * cleanup takes non-trivial time. */
    sig_atomic_t cpgid = active_child_pgid;
    if (cpgid > 0) {
        (void) kill(-(pid_t) cpgid, signum);
    }

    /* Clean up global keymgr (securely zero master key) */
    keymgr_cleanup_global();

    /* Re-raise signal with default handler to ensure proper exit */
    signal(signum, SIG_DFL);
    raise(signum);
}

int main(int argc, char **argv) {
    /* Initialize libgit2 */
    if (git_libgit2_init() < 0) {
        fprintf(stderr, "Failed to initialize libgit2\n");
        return 1;
    }

    /* Initialize libhydrogen */
    error_t *init_err = encryption_init();
    if (init_err) {
        fprintf(
            stderr, "Failed to initialize encryption: %s\n",
            error_message(init_err)
        );
        error_free(init_err);
        git_libgit2_shutdown();
        return 1;
    }

    /* Register cleanup handlers for graceful shutdown
     * This ensures encryption keys are cleared from memory on exit */
    atexit(keymgr_cleanup_global);
    signal(SIGINT, signal_cleanup_handler);   /* Ctrl+C */
    signal(SIGTERM, signal_cleanup_handler);  /* kill command */

    /* Ignore SIGPIPE so writes to broken pipes return EPIPE instead of
     * killing dotta. Required for any code path that streams output to a
     * caller-controlled fd (e.g., bootstrap scripts whose stdout the user
     * may pipe to a head/grep that closes early). */
    signal(SIGPIPE, SIG_IGN);

    /* Root-level dispatch resolution — pure data projection of the
     * registry. No config/output needed for help/version/usage, so
     * resolve first and let those branches exit early without paying
     * for config loading. */
    const args_command_t *spec = NULL;
    switch (args_resolve_root(dotta_commands, argc, argv, &spec)) {
        case ARGS_ROOT_NONE:
            args_render_root_usage(stderr, dotta_commands, argv[0]);
            git_libgit2_shutdown();
            return 1;
        case ARGS_ROOT_HELP:
            args_render_root_usage(stdout, dotta_commands, argv[0]);
            git_libgit2_shutdown();
            return 0;
        case ARGS_ROOT_VERSION:
            version_print(stdout);
            git_libgit2_shutdown();
            return 0;
        case ARGS_ROOT_UNKNOWN:
            fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
            args_render_root_usage(stderr, dotta_commands, argv[0]);
            git_libgit2_shutdown();
            return 1;
        case ARGS_ROOT_COMMAND:
            break;
    }

    /* Load configuration once for entire process.
     * Non-fatal: if config file is missing or invalid, use defaults. */
    config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        error_free(cfg_err);
        config = config_create_default();
    }
    if (!config) {
        fprintf(stderr, "Failed to create configuration\n");
        git_libgit2_shutdown();
        return 1;
    }

    /* Create output context once from config settings.
     * All commands share this context and may override verbosity via CLI flags. */
    output_ctx_t *out = output_create(
        stdout,
        output_parse_verbosity(config->verbosity),
        output_parse_color_mode(config->color)
    );
    if (!out) {
        fprintf(stderr, "Failed to create output context\n");
        config_free(config);
        git_libgit2_shutdown();
        return 1;
    }

    int ret = run_spec(spec, argc, argv, config, out);

    /* Fix repository ownership if running under sudo
     *
     * This ensures that .git/ files created during privileged operations
     * (e.g., sudo dotta update crypto) are owned by the original user, not root.
     * Without this fix, subsequent non-sudo operations would fail with
     * "Permission denied" when trying to access root-owned files.
     *
     * When: After all Git operations complete, before shutdown
     * Why: Catches all root-owned files created during this run
     * Where: Only when running under sudo (automatic detection)
     * Error handling: Log warning but don't change exit code (non-fatal)
     */
    if (privilege_is_sudo()) {
        char *repo_path = NULL;
        error_t *err = resolve_repo_path(config, &repo_path);

        if (!err) {
            /* Fix ownership of .git directory */
            err = repo_fix_ownership_if_needed(repo_path);
            if (err) {
                /* Non-fatal: warn user but don't fail the command
                 * The command itself succeeded, ownership fix is just cleanup */
                fprintf(stderr, "\nWarning: Failed to fix repository ownership\n");
                fprintf(stderr, "The repository may be inaccessible without sudo.\n");
                fprintf(stderr, "To fix manually, run:\n");
                fprintf(stderr, "  sudo chown -R $USER:$GROUP %s/.git\n\n", repo_path);
                error_print(err, stderr);
                error_free(err);
            }
            free(repo_path);
        } else {
            /* Path resolution failed - unusual but non-fatal
             * Likely means we're in a context where there's no repo (e.g., init) */
            error_free(err);
        }
    }

    git_libgit2_shutdown();
    output_free(out);
    config_free(config);

    return ret;
}
