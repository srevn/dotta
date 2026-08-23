/**
 * main.c - Dotta entry point
 *
 * Dotfile manager using git branches as profiles.
 */

#include <git2.h>
#include <runtime.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "sys/process.h"
#include "cmds/add.h"
#include "cmds/apply.h"
#include "cmds/bootstrap.h"
#include "cmds/clone.h"
#include "cmds/completion.h"
#include "cmds/diff.h"
#include "cmds/export.h"
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
#include "cmds/show.h"
#include "cmds/status.h"
#include "cmds/sync.h"
#include "cmds/update.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "crypto/keymgr.h"
#include "infra/content.h"
#include "infra/salt.h"
#include "utils/config.h"
#include "utils/privilege.h"
#include "utils/repo.h"
#include "utils/version.h"

/**
 * Root command registry — every user-facing top-level command.
 *
 * The single place that names every command the CLI exposes. Two consumers project
 * this array into behavior:
 *
 *   - args_resolve_root / args_render_root_usage — direct calls from main,
 *     resolving argv[1] and rendering top-level help;
 *   - cmds/completion.c — the fish completion exporter and the candidates
 *     driver reach the array through dotta_registry() so the cmds layer never
 *     names the registry symbol.
 *
 * Ordered for root-help readability: setup → file ops → deploy/undo → inspect →
 * remote → profile/remote mgmt → config → passthrough → special. Every projection
 * (dispatch, help, fish export) walks this array, so the order is the display
 * order everywhere. NULL-terminated for `for (size_t i = 0; reg[i] != NULL; i++)`
 * loops.
 */
static const args_command_t *const dotta_commands[] = {
    &spec_init,     &spec_clone,      &spec_add,
    &spec_remove,   &spec_update,     &spec_apply,
    &spec_revert,   &spec_status,     &spec_diff,
    &spec_list,     &spec_show,       &spec_export,
    &spec_sync,     &spec_profile,    &spec_remote,
    &spec_ignore,   &spec_bootstrap,  &spec_key,
    &spec_git,      &spec_completion, &spec_interactive,
    &spec_complete,
    NULL
};

/**
 * Typed public face of the file-local `dotta_commands` registry.
 *
 * Only consumer today is `cmds/completion.c`, which projects the registry into
 * the fish-completion dialect when the build emits
 * `build/completions/dotta-completions.fish`. Keeping the storage `static` and
 * exposing it through this accessor lets the cmds/ layer read the array without
 * compile-depending on the symbol.
 */
const args_command_t *const *dotta_registry(void) {
    return dotta_commands;
}

/**
 * Open the run: every member the spec declares, in dependency order.
 *
 * The needs are checked for closure first — the spec names the full set its
 * handler reads, and the set must hold its own inputs (runtime.h). Then the
 * repository, state, the crypto handles, the mount table and the view, each
 * iff declared; every member starts NULL and is populated in place, so on an
 * error the members already opened are exactly what `close_run` releases.
 *
 * The first open that fails returns its own error — it names the resource and,
 * for the salt and the view, the repair — and the run stays partially open for
 * `close_run`. Under `tolerant` the same failure ends the open silently: what
 * opened stays, the rest is NULL, and the handler runs with that shape.
 */
static error_t *open_run(
    dotta_run_t *run,
    const dotta_needs_t *needs,
    const config_t *config,
    arena_t *arena
) {
    /* Closure: a derived member's input is declared beside it. An incoherent
     * spec is a programming error, caught on the command's first run. */
    bool has_state = needs->state != DOTTA_STATE_NONE;
    CHECK_ARG(!has_state || needs->repo, "Spec declares state without repo");
    CHECK_ARG(!needs->crypto || needs->repo, "Spec declares crypto without repo");
    CHECK_ARG(!needs->mounts || has_state, "Spec declares mounts without state");
    CHECK_ARG(!needs->manifest || has_state, "Spec declares manifest without state");

    error_t *err = NULL;

    /* The repository and its path. `repo_open` resolves the path to open the
     * repo; the run keeps an arena copy so it holds no heap string. */
    if (needs->repo) {
        char *repo_path = NULL;
        err = repo_open(config, &run->repo, &repo_path);
        if (err) goto done;

        run->repo_path = arena_strdup(arena, repo_path);
        free(repo_path);
        if (!run->repo_path) {
            err = ERROR(ERR_MEMORY, "Failed to copy repository path");
            goto done;
        }
    }

    /* State, in the shape the spec declared. A WRITE handle holds BEGIN
     * IMMEDIATE for the whole dispatch; the command calls state_save, and
     * close_run's state_free rolls back anything it did not. */
    if (has_state) {
        err = (needs->state == DOTTA_STATE_WRITE) ? state_open(run->repo, &run->state)
                                                  : state_load(run->repo, &run->state);
        if (err) goto done;
    }

    /* The crypto handles: the keymgr iff encryption is enabled, the content
     * cache always (possibly with a NULL keymgr — see runtime.h's crypto
     * rationale). */
    if (needs->crypto) {
        if (config->encryption_enabled) {
            /* Load the per-repo Argon2id salt from refs/dotta/salt before
             * constructing the keymgr — the salt is part of the master-key
             * derivation contract, so the keymgr cannot exist without it. */
            uint8_t salt[KDF_SALT_SIZE];
            err = salt_load(run->repo, salt);
            if (err) {
                if (err->code == ERR_NOT_FOUND) {
                    err = error_wrap(
                        err,
                        "Encryption requires repository config (%s)\n"
                        "  - For new repositories: run 'dotta init'\n"
                        "  - For clones: re-run with the salt fetched "
                        "(remote may not be a dotta v7 repository)",
                        SALT_REF
                    );
                }
                goto done;
            }

            err = keymgr_create(config, salt, &run->keymgr);
            /* Salt is public; no wipe needed. The keymgr has copied it into its
             * own storage. */
            if (err) goto done;
        }

        run->content_cache = content_cache_create(run->repo, run->keymgr);
        if (!run->content_cache) {
            err = ERROR(ERR_MEMORY, "Failed to create content cache");
            goto done;
        }
    }

    /* The mount table built from the state's rows — the topology at dispatch,
     * for classifying the command's input. The arena's; nothing to close. */
    if (needs->mounts) {
        mount_table_t *mounts = NULL;
        err = profile_build_mount_table(run->state, arena, &mounts);
        if (err) goto done;
        run->mounts = mounts;
    }

    /* The view over the enabled set as it stands. The builder's error is
     * returned as it is: it names the profile and, for a custom/ path under a
     * profile with no target, the repair. The rows land in the command arena;
     * the index is close_run's to release. */
    if (needs->manifest) {
        err = manifest_build(run->repo, run->state, arena, &run->manifest);
        if (err) goto done;
    }

done:
    if (err && needs->tolerant) {
        error_free(err);
        err = NULL;
    }
    return err;
}

/**
 * Close the run: LIFO over what open_run opened.
 *
 * The view's index first (its rows are the arena's), then the content cache
 * (holds a borrowed keymgr pointer but does not dereference it at teardown),
 * then the keymgr, then state (state_free auto-rolls-back any uncommitted
 * transaction per state.h's contract), then the repository. The mount table and
 * the repository path are the arena's. Every dotta primitive is NULL-safe, so
 * a run that opened partway — an acquisition error, or a tolerant open that
 * stopped early — closes the same way as a whole one.
 */
static void close_run(dotta_run_t *run) {
    manifest_free(run->manifest);
    content_cache_free(run->content_cache);
    keymgr_free(run->keymgr);
    state_free(run->state);
    if (run->repo != NULL) git_repository_free(run->repo);
}

/**
 * Parse, dispatch, and cleanup for one spec-engine command.
 *
 * Owns a command-scoped arena (destroyed before return) and the run that is
 * opened into it. Follows the parse → open → dispatch → close sequence. Never
 * calls exit(); the caller's cleanup chain is preserved unchanged.
 */
static int run_spec(
    const args_command_t *cmd,
    int argc, char **argv,
    const config_t *config,
    output_t *out
) {
    const char *prog = argv[0];

    /* Command-scoped arena. Sized for the median command — parsing needs ~few
     * KB, but workspace/scope/manifest paths fit ~140 KB worst case in one or
     * two blocks at this initial size. Borrowed by handlers via ctx->arena and
     * by every derived member of the run; destroyed below. */
    arena_t *arena = arena_create(32UL * 1024);
    if (arena == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    /* `resolved` tracks the leaf command after subcommand resolution. For a flat
     * command this stays equal to `cmd`; for a tree it is the matched child (so
     * help and errors render against the actual subcommand the user typed, and
     * dispatch goes to its handler). */
    const args_command_t *resolved = cmd;

    /* Passthrough commands (e.g. `git`) skip parsing but still open their run,
     * so the repository path reaches dispatch without a second `repo_open`. */
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

        /* Parse. The engine resets `errors` in-place, so the uninitialized stack
         * declaration is intentional. */
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

    /* The spec's needs — every run member its handler reads (runtime.h); a
     * spec without a payload opens nothing. The context is zero-initialised:
     * open_run populates the run in place, and what it opened is what
     * close_run releases, on every path. */
    int exit_override = 0;
    dotta_ctx_t ctx = {
        .arena     = arena,
        .config    = config,
        .out       = out,
        .argc      = argc,
        .argv      = argv,
        .exit_code = &exit_override,
    };

    const dotta_needs_t *needs = resolved->payload;
    error_t *err = needs != NULL ? open_run(&ctx.run, needs, config, arena) : NULL;
    if (err == NULL) err = resolved->dispatch(&ctx, opts);

    close_run(&ctx.run);
    arena_destroy(arena);

    /* One line renders every failure — an open that refused and a handler
     * that did, under the same flag. */
    if (err != NULL) {
        if (!resolved->silent_failure) error_print(err, stderr);
        error_free(err);
        return 1;
    }
    /* Passthrough dispatch writes via *ctx->exit_code to propagate the child's
     * exact status (0, 1, 2, 128+n). Native commands leave it at 0. */
    return exit_override;
}

/* Definition of the cross-TU symbol declared in sys/process.h. Published by
 * sys/process.c::process_run() while a PROCESS_PGRP_NEW child is alive; zero
 * otherwise. The signal handler below reads it to forward terminating signals
 * to the child's process group before dotta dies, so a Ctrl+C kills both atomically
 * rather than orphaning the spawned hook.
 *
 * PROCESS_PGRP_SHARED children leave this at zero — the kernel already delivers
 * terminal SIGINT/SIGTERM to the entire foreground group, so parent and child
 * receive it without forwarding. */
volatile sig_atomic_t active_child_pgid = 0;

/**
 * Signal handler for SIGINT/SIGTERM
 *
 * Forwards the signal to any active child process group (so a hook dies atomically
 * with dotta) and re-raises with the default disposition so the kernel can
 * terminate the process.
 *
 * No resource cleanup runs here by design. Signal handlers must stay AS-safe
 * per POSIX SUSv4 §2.4.3 — which rules out malloc/free (needed by libgit2 teardown)
 * and crypto_wipe/munlock (needed by keymgr teardown). The kernel reclaims mlocked
 * pages on process death and zeroes them before reallocation, so master keys
 * held in the now-freed keymgr cannot surface in another process's memory.
 * Worktrees are orphan-cleaned by worktree.c on the next invocation, and SQLite
 * WAL mode auto-rolls-back any in-flight transaction.
 *
 * AS-safe primitives used: kill(2), signal(2), raise(3) per SUSv4 §2.4.3. Reading
 * volatile sig_atomic_t is atomic by definition.
 */
static void signal_cleanup_handler(int signum) {
    /* Forward first, so the child group starts dying even if the default
     * disposition takes non-trivial time to kick in. */
    sig_atomic_t cpgid = active_child_pgid;
    if (cpgid > 0) {
        (void) kill(-(pid_t) cpgid, signum);
    }

    /* Re-raise signal with default handler to ensure proper exit */
    signal(signum, SIG_DFL);
    raise(signum);
}

int main(int argc, char **argv) {
    /* Line-buffer the report
     *
     * dotta writes one document to stdout and, from several layers, diagnostics
     * to stderr: the terminal failure and the prompts from base/output, and the
     * raw state-corruption notes that core/ emits where it has no output context.
     * stderr is never fully buffered (POSIX), while stdout is block-buffered
     * the moment it is not a terminal — so a redirected run reads back with every
     * diagnostic hoisted above the report it annotates, and the heading of a
     * block separated from its list.
     *
     * Flush granularity is what differs, so flush granularity is what is fixed:
     * one line, matching stderr's, makes the order the reader sees the order
     * the code wrote, for every writer in every layer. The report is at most a
     * few hundred lines and never bulk data (the machine-readable command,
     * completion, bypasses this stream), so the extra write(2) per line buys
     * ordering at no cost worth naming.
     *
     * Set before anything can print — the libgit2 failure below included.
     */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Initialize libgit2 */
    if (git_libgit2_init() < 0) {
        fprintf(stderr, "Failed to initialize libgit2\n");
        return 1;
    }

    /* Install signal handlers so child process groups (spawned hooks) get forwarded
     * terminal signals atomically with dotta. Keymgr teardown is command-scoped
     * and happens via keymgr_free on the dispatch return path, not here — see
     * signal_cleanup_handler. */
    signal(SIGINT, signal_cleanup_handler);   /* Ctrl+C */
    signal(SIGTERM, signal_cleanup_handler);  /* kill command */

    /* Ignore SIGPIPE so writes to broken pipes return EPIPE instead of killing
     * dotta. Required for any code path that streams output to a caller-controlled
     * fd (e.g., bootstrap scripts whose stdout the user may pipe to a head/grep
     * that closes early). */
    signal(SIGPIPE, SIG_IGN);

    /* Root-level dispatch resolution — pure data projection of the registry. No
     * config/output needed for help/version/usage, so resolve first and let those
     * branches exit early without paying for config loading. */
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
     *
     * config_load handles the missing-config-file case internally (returns defaults
     * with no error). Any error returned here is a real failure — parse error,
     * unknown key, invalid value, or a malformed auto-encrypt pattern — and must
     * surface, not fall back silently to defaults that hide the user's mistake. */
    config_t *config = NULL;
    error_t *cfg_err = config_load(NULL, &config);
    if (cfg_err) {
        fprintf(
            stderr, "Failed to load configuration: %s\n",
            error_message(cfg_err)
        );
        error_free(cfg_err);
        git_libgit2_shutdown();
        return 1;
    }

    /* Create output context once from config settings. All commands share this
     * context and may override verbosity via CLI flags. */
    output_t *out = output_create(
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
     * This ensures that .git/ files created during privileged operations (e.g.,
     * sudo dotta update crypto) are owned by the original user, not root. Without
     * this fix, subsequent non-sudo operations would fail with "Permission denied"
     * when trying to access root-owned files.
     *
     * When: After all Git operations complete, before shutdown Why: Catches all
     * root-owned files created during this run Where: Only when running under
     * sudo (automatic detection) Error handling: Log warning but don't change
     * exit code (non-fatal)
     */
    if (privilege_is_sudo()) {
        char *repo_path = NULL;
        error_t *err = resolve_repo_path(config, &repo_path);

        if (!err) {
            /* Fix ownership of .git directory */
            err = repo_fix_ownership_if_needed(repo_path);
            if (err) {
                /* Non-fatal: warn user but don't fail the command The command
                 * itself succeeded, ownership fix is just cleanup */
                fprintf(stderr, "\nWarning: Failed to fix repository ownership\n");
                fprintf(stderr, "The repository may be inaccessible without sudo.\n");
                fprintf(stderr, "To fix manually, run:\n");
                fprintf(stderr, "  sudo chown -R $USER:$GROUP %s/.git\n\n", repo_path);
                error_print(err, stderr);
                error_free(err);
            }
            free(repo_path);
        } else {
            /* Path resolution failed - unusual but non-fatal Likely means we're
             * in a context where there's no repo (e.g., init) */
            error_free(err);
        }
    }

    git_libgit2_shutdown();
    output_free(out);
    config_free(config);

    return ret;
}
