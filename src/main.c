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
#include "cmds/show.h"
#include "cmds/status.h"
#include "cmds/sync.h"
#include "cmds/update.h"
#include "core/state.h"
#include "crypto/keymgr.h"
#include "infra/content.h"
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
 *   - args_resolve_root / args_render_root_usage — direct calls
 *     from main, resolving argv[1] and rendering top-level help;
 *   - the fish completion exporter in cmds/completion.c — reaches
 *     the array through dotta_registry() so the cmds layer never
 *     names the registry symbol.
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

/* Per-combination dispatch payloads — one const per (repo_mode,
 * state_mode) pair actually used by the registry. Each command's spec
 * sets `.payload = &dotta_ext_X` for its needed pair; the dispatcher
 * reads it back in `run_spec` to decide how to acquire the repository
 * and state handles before calling the handler. Only the combinations
 * used in the registry are defined; new pairings earn new constants. */
const dotta_spec_ext_t dotta_ext_none = {
    .repo_mode  = DOTTA_REPO_NONE,
    .state_mode = DOTTA_STATE_NONE,
};
const dotta_spec_ext_t dotta_ext_path_only = {
    .repo_mode  = DOTTA_REPO_PATH_ONLY,
    .state_mode = DOTTA_STATE_NONE,
};
const dotta_spec_ext_t dotta_ext_repo_only = {
    .repo_mode  = DOTTA_REPO_REQUIRED,
    .state_mode = DOTTA_STATE_NONE,
};
const dotta_spec_ext_t dotta_ext_read = {
    .repo_mode  = DOTTA_REPO_REQUIRED,
    .state_mode = DOTTA_STATE_READ,
};
const dotta_spec_ext_t dotta_ext_write = {
    .repo_mode  = DOTTA_REPO_REQUIRED,
    .state_mode = DOTTA_STATE_WRITE,
};
const dotta_spec_ext_t dotta_ext_read_silent = {
    .repo_mode  = DOTTA_REPO_OPTIONAL_SILENT,
    .state_mode = DOTTA_STATE_READ,
};
const dotta_spec_ext_t dotta_ext_read_key = {
    .repo_mode   = DOTTA_REPO_REQUIRED,
    .state_mode  = DOTTA_STATE_READ,
    .crypto_mode = DOTTA_CRYPTO_KEY,
};
const dotta_spec_ext_t dotta_ext_write_key = {
    .repo_mode   = DOTTA_REPO_REQUIRED,
    .state_mode  = DOTTA_STATE_WRITE,
    .crypto_mode = DOTTA_CRYPTO_KEY,
};
const dotta_spec_ext_t dotta_ext_read_crypto = {
    .repo_mode   = DOTTA_REPO_REQUIRED,
    .state_mode  = DOTTA_STATE_READ,
    .crypto_mode = DOTTA_CRYPTO_KEY_CACHE,
};
const dotta_spec_ext_t dotta_ext_write_crypto = {
    .repo_mode   = DOTTA_REPO_REQUIRED,
    .state_mode  = DOTTA_STATE_WRITE,
    .crypto_mode = DOTTA_CRYPTO_KEY_CACHE,
};

/**
 * Typed public face of the file-local `dotta_commands` registry.
 *
 * Only consumer today is `cmds/completion.c`, which projects the
 * registry into the fish-completion dialect when the build emits
 * `build/completions/dotta-completions.fish`. Keeping the storage
 * `static` and exposing it through this accessor lets the cmds/
 * layer read the array without compile-depending on the symbol.
 */
const args_command_t *const *dotta_registry(void) {
    return dotta_commands;
}

/**
 * Open a repository handle according to the command's declared mode.
 *
 * Returns 0 on success, 1 on unrecoverable error (error is printed).
 * On success, `*repo_out` and `*path_out` are set per mode:
 *
 *   DOTTA_REPO_NONE            → both NULL
 *   DOTTA_REPO_REQUIRED        → repo set, path set
 *   DOTTA_REPO_OPTIONAL_SILENT → repo maybe NULL, path NULL, no errors
 *   DOTTA_REPO_PATH_ONLY       → repo NULL (released), path set
 *
 * Invariant: whenever `*repo_out` is non-NULL on return, `*path_out` is
 * non-NULL too. `repo_open` already resolves the path to open the repo;
 * threading it out costs nothing and gives commands that need both
 * (e.g. bootstrap, which exports DOTTA_REPO_DIR to child scripts) a
 * single source of truth instead of a second `resolve_repo_path` call.
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
            error_t *err = repo_open(config, repo_out, path_out);
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
 * Acquire a state handle according to the command's declared mode.
 *
 * Returns 0 on success, 1 on unrecoverable error (error is printed).
 * On success, `*state_out` is set per mode:
 *
 *   DOTTA_STATE_NONE   → NULL
 *   DOTTA_STATE_READ   → state_load handle (may be state_empty on missing DB)
 *   DOTTA_STATE_WRITE  → state_open handle (BEGIN IMMEDIATE held)
 *
 * Parallel in shape to `open_repo_for_mode`. No state is acquired when
 * `repo == NULL`: DOTTA_REPO_NONE commands and DOTTA_REPO_OPTIONAL_SILENT
 * commands that found no repo silently skip the mode — the missing repo
 * is a valid dispatch outcome, not an error condition for state.
 *
 * On WRITE acquisition, the transaction lives for the full dispatch;
 * the command calls `state_save` when its mutation is complete. On
 * failure paths or uncommitted exits, `state_free` in the dispatcher
 * auto-rolls-back per state.h's teardown contract.
 */
static int open_state_for_mode(
    dotta_state_mode_t mode,
    git_repository *repo,
    state_t **state_out
) {
    *state_out = NULL;

    if (mode == DOTTA_STATE_NONE || repo == NULL) return 0;

    error_t *err = (mode == DOTTA_STATE_WRITE) ? state_open(repo, state_out)
                                               : state_load(repo, state_out);
    if (err != NULL) {
        error_print(err, stderr);
        error_free(err);
        return 1;
    }
    return 0;
}

/**
 * Acquire crypto handles according to the command's declared mode.
 *
 * Returns 0 on success, 1 on unrecoverable error (error is printed).
 * On success, `*keymgr_out` and `*cache_out` are set per mode:
 *
 *   DOTTA_CRYPTO_NONE       → both NULL
 *   DOTTA_CRYPTO_KEY        → keymgr set iff encryption enabled;   cache NULL
 *   DOTTA_CRYPTO_KEY_CACHE  → cache always set; keymgr set iff encryption enabled
 *
 * Parallel in shape to `open_repo_for_mode` and `open_state_for_mode`.
 * No crypto is acquired when `repo == NULL` (content_cache needs a repo
 * to read blobs from, and a standalone keymgr has no use site downstream).
 *
 * Under KEY_CACHE with encryption disabled, the cache is still created
 * with a NULL keymgr; it handles plaintext blobs uniformly and surfaces
 * ERR_CRYPTO on any decrypt attempt — per the runtime.h invariant on
 * `ctx->content_cache`.
 */
static int open_crypto_for_mode(
    dotta_crypto_mode_t mode,
    git_repository *repo,
    const config_t *config,
    keymgr **keymgr_out,
    content_cache_t **cache_out
) {
    *keymgr_out = NULL;
    *cache_out = NULL;

    if (mode == DOTTA_CRYPTO_NONE || repo == NULL) return 0;

    if (config->encryption_enabled) {
        error_t *err = keymgr_create(config, keymgr_out);
        if (err != NULL) {
            error_print(err, stderr);
            error_free(err);
            return 1;
        }
    }

    if (mode == DOTTA_CRYPTO_KEY) return 0;

    /* KEY_CACHE: cache always created, possibly with NULL keymgr. */
    *cache_out = content_cache_create(repo, *keymgr_out);
    if (*cache_out == NULL) {
        keymgr_free(*keymgr_out);
        *keymgr_out = NULL;
        fprintf(stderr, "Failed to create content cache\n");
        return 1;
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
    output_t *out
) {
    const char *prog = argv[0];

    /* Command-scoped arena. Sized for the median command — parsing
     * needs ~few KB, but workspace/scope/manifest paths fit ~140 KB
     * worst case in one or two blocks at this initial size.
     * Borrowed by handlers via ctx->arena; destroyed below. */
    arena_t *arena = arena_create(32 * 1024);
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

    /* Each command's spec stashes its dispatch preconditions in `payload`
     * via a `dotta_spec_ext_t` constant. NULL falls back to NONE/NONE/NONE
     * so a spec that omits payload simply gets no handles. */
    const dotta_spec_ext_t *ext = resolved->payload;
    dotta_repo_mode_t repo_mode = ext != NULL ? ext->repo_mode : DOTTA_REPO_NONE;
    dotta_state_mode_t state_mode = ext != NULL ? ext->state_mode : DOTTA_STATE_NONE;
    dotta_crypto_mode_t crypto_mode = ext != NULL ? ext->crypto_mode : DOTTA_CRYPTO_NONE;

    git_repository *repo = NULL;
    char *repo_path = NULL;
    state_t *state = NULL;
    keymgr *keymgr = NULL;
    content_cache_t *cache = NULL;

    if (open_repo_for_mode(repo_mode, config, &repo, &repo_path) != 0) {
        arena_destroy(arena);
        return 1;
    }
    if (open_state_for_mode(state_mode, repo, &state) != 0) {
        if (repo != NULL) git_repository_free(repo);
        free(repo_path);
        arena_destroy(arena);
        return 1;
    }
    if (open_crypto_for_mode(crypto_mode, repo, config, &keymgr, &cache) != 0) {
        state_free(state);
        if (repo != NULL) git_repository_free(repo);
        free(repo_path);
        arena_destroy(arena);
        return 1;
    }

    int exit_override = 0;
    dotta_ctx_t ctx = {
        .repo          = repo,
        .repo_path     = repo_path,
        .state         = state,
        .keymgr        = keymgr,
        .content_cache = cache,
        .arena         = arena,
        .config        = config,
        .out           = out,
        .argc          = argc,
        .argv          = argv,
        .exit_code     = &exit_override,
    };

    error_t *err = resolved->dispatch(&ctx, opts);

    /* LIFO teardown. content_cache first (holds a borrowed keymgr pointer
     * but does not dereference it at teardown), then keymgr, then state
     * (state_free auto-rolls-back any uncommitted transaction per state.h's
     * contract). All *_free primitives are NULL-safe. */
    content_cache_free(cache);
    keymgr_free(keymgr);
    state_free(state);
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
 * Signal handler for SIGINT/SIGTERM
 *
 * Forwards the signal to any active child process group (so a hook
 * dies atomically with dotta) and re-raises with the default disposition
 * so the kernel can terminate the process.
 *
 * No resource cleanup runs here by design. Signal handlers must stay
 * AS-safe per POSIX SUSv4 §2.4.3 — which rules out malloc/free (needed
 * by libgit2 teardown) and crypto_wipe/munlock (needed by keymgr
 * teardown). The kernel reclaims mlocked pages on process death and
 * zeroes them before reallocation, so master keys held in the now-freed
 * keymgr cannot surface in another process's memory. Worktrees are
 * orphan-cleaned by worktree.c on the next invocation, and SQLite WAL
 * mode auto-rolls-back any in-flight transaction.
 *
 * AS-safe primitives used: kill(2), signal(2), raise(3) per SUSv4
 * §2.4.3. Reading volatile sig_atomic_t is atomic by definition.
 */
static void signal_cleanup_handler(int signum) {
    /* Forward first, so the child group starts dying even if the
     * default disposition takes non-trivial time to kick in. */
    sig_atomic_t cpgid = active_child_pgid;
    if (cpgid > 0) {
        (void) kill(-(pid_t) cpgid, signum);
    }

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

    /* Install signal handlers so child process groups (spawned hooks)
     * get forwarded terminal signals atomically with dotta. Keymgr
     * teardown is command-scoped and happens via keymgr_free on the
     * dispatch return path, not here — see signal_cleanup_handler. */
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
     *
     * config_load handles the missing-config-file case internally
     * (returns defaults with no error). Any error returned here is a
     * real failure — parse error, unknown key, invalid value, or a
     * malformed auto-encrypt pattern — and must surface, not fall back
     * silently to defaults that hide the user's mistake. */
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

    /* Create output context once from config settings.
     * All commands share this context and may override verbosity via CLI flags. */
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
