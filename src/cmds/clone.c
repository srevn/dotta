/**
 * clone.c - Clone dotta repository implementation
 *
 * The clone is init with a remote: the bare store created and declared
 * (utils/repo.h), the remote added and met once (sys/remote.h) — its advertisement
 * of the epoch the identity gate, then one fetch of every branch it advertises
 * and of the epoch, the epoch adopted — and the chosen profiles made local from
 * what landed. No `git_clone`: that call creates a local branch for the remote's
 * HEAD whatever was asked for, and dotta's store has no branch nobody asked for.
 *
 * Smart profile management
 * - Auto-detects relevant profiles by default
 * - Makes only detected/specified profiles local
 * - Initializes state with those profiles
 * - Supports hub mode (--all) for backup workflows
 */

#include "cmds/clone.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/commit.h"
#include "infra/epoch.h"
#include "sys/bootstrap.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/remote.h"
#include "sys/upstream.h"
#include "utils/bootstrap.h"
#include "utils/repo.h"

/**
 * Make the chosen profiles local
 *
 * The one fetch has run (sys/remote.h remote_fetch): every branch the remote
 * advertised stands under refs/remotes/<remote>. Each chosen name becomes a local
 * branch at that commit; a name the remote does not have is warned about by name
 * and skipped, so a `-p` typo costs one profile and not the clone. The warnings
 * are one block, beneath whatever stood: its boundary is asked here, and paid
 * by the first of them or, where none prints, by the line the caller says next.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (typically "origin")
 * @param profiles Array of profile names to make local, each once (may be NULL
 *                 when count is 0: the entries of an empty listing, a remote
 *                 with no branch)
 * @param count Number of profiles
 * @param out Output context for messages
 * @param landed Array the names made local are pushed to, in order (must not be
 *               NULL)
 */
static void land_profiles(
    git_repository *repo,
    const char *remote_name,
    char **profiles,
    size_t count,
    output_t *out,
    string_array_t *landed
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    CHECK_NULL(landed);

    output_gap(out, OUTPUT_NORMAL);
    for (size_t i = 0; i < count; i++) {
        const char *profile = profiles[i];

        /* The local branch, created at the remote's commit: each name comes once,
         * into a store the clone just made. A name that fails is warned about
         * and skipped, its error dropped, one per such name. */
        error_t err = upstream_ensure_tracking_branch(
            repo, remote_name, profile, commit_action_word(COMMIT_ACTION_CLONE)
        );
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to create local branch '%s': %s",
                profile, error_line(err)
            );
            continue;
        }

        string_array_push(landed, profile);
    }
}

/**
 * Initialize state with the profiles clone enables
 *
 * Creates the database whatever `profiles` holds, enables exactly the names given
 * — the caller decided which fetched profiles this machine can place — and names
 * them when there are any.
 *
 * @param repo Repository
 * @param arena Arena the view is built in and the names are joined in
 * @param profiles Profile names to set as enabled (must not be NULL; may be empty)
 * @param out Output context
 * @return Error or NULL on success
 */
static error_t initialize_state(
    git_repository *repo,
    arena_t *arena,
    const string_array_t *profiles,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    /* Create state database (with or without profiles) */
    state_t *state = NULL;
    error_t err = state_open(repo, &state);
    if (err) return err;

    /* Enable each profile individually, then build the view over the new set once.
     *
     * state_enable_profile is the membership primitive — clone calls it once
     * per profile, always with target=NULL: the caller hands it only profiles
     * that need no target here, so there is nothing to bind, and a per-machine
     * target is enable's to give later.
     *
     * The view is computed, never stored: the build writes nothing and its result
     * is discarded. It is the tripwire that keeps clone from landing an enabled
     * set the next load cannot build — a branch that exists but will not load
     * fails here, before state_save, and the repository is left with nothing
     * enabled. Every step meets the handle's one release: a refusal names its
     * profile or its store itself. */
    for (size_t i = 0; !err && i < profiles->count; i++) {
        err = state_enable_profile(state, profiles->entries[i], NULL);
    }
    if (!err && profiles->count > 0) {
        manifest_t *view = NULL;
        err = manifest_build(repo, state, arena, &view);
    }

    /* Commit transaction */
    if (!err) err = state_save(state);
    state_free(state);
    if (err) return err;

    /* The names enabled, when there are any: a run that enabled nothing said
     * why per profile above, and has no list to print. The state is a phase of
     * its own, its line the fetch's summary's next where nothing stands between
     * them. */
    if (profiles->count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Initialized enabled profiles: %s",
            string_array_join(arena, profiles, ", ")
        );
    }

    return NULL;
}

/**
 * Remove what a failed clone left behind.
 *
 * Clone's entire side-effect surface is the target directory — the store is bare,
 * so the record, the refs and the objects all live in it — so all-or-nothing
 * means one thing: after a fatal error, nothing dotta created remains. A
 * pre-existing (empty) target directory is kept and only emptied; a directory
 * the clone created is removed outright. Best-effort — the fatal error being
 * unwound still stands, so a removal failure only warns.
 */
static void rollback_clone_dir(
    const dotta_ctx_t *ctx,
    const char *path,
    bool path_preexisted
) {
    error_t err = NULL;

    if (path_preexisted) {
        string_array_t listing = { 0 };
        err = fs_list_dir(path, ctx->arena, &listing);
        for (size_t i = 0; i < listing.count && !err; i++) {
            err = fs_clear_path(str_path_join(ctx->arena, path, listing.entries[i]));
        }
    } else {
        err = fs_remove_dir(path);
    }

    /* Either outcome a block of its own, beneath what the clone said before it
     * failed */
    output_gap(ctx->out, OUTPUT_NORMAL);
    if (err) {
        output_warning(
            ctx->out, OUTPUT_NORMAL, "Failed to remove partial clone at %s: %s",
            path, error_line(err)
        );
        output_hint(ctx->out, OUTPUT_NORMAL, "Remove it manually before retrying");
        return;
    }

    output_info(ctx->out, OUTPUT_NORMAL, "Rolled back partial clone at %s", path);
}

/**
 * Clone command implementation
 */
error_t cmd_clone(const dotta_ctx_t *ctx, const cmd_clone_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->url);

    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t err = NULL;
    git_repository *repo = NULL;
    const char *local_path = NULL;
    const char *elsewhere = NULL;
    bool path_preexisted = false;
    bool clone_landed = false;
    remote_t *remote = NULL;

    /* Where the repository goes: the positional when one was given, this machine's
     * configured location otherwise — one answer, expanded, absolute and with
     * its parents created (utils/repo.h). Absolute matters twice over here: the
     * bootstrap below hands it to a script as $DOTTA_REPO_DIR, and the rollback
     * removes it. */
    err = repo_create_target(config, ctx->arena, opts->path, &local_path, &elsewhere);
    if (err) goto cleanup;

    output_section(out, OUTPUT_NORMAL, "Cloning dotta repository");
    output_info(out, OUTPUT_NORMAL, "  URL: %s", opts->url);
    output_info(out, OUTPUT_NORMAL, "  Path: %s", local_path);

    /* The place the clone lands must be absent or an empty directory. What stands
     * there is somebody's: a repository would be taken by the init below, and
     * files beside a store the rollback empties would go with it. A directory
     * that predates the clone is kept by the rollback and only emptied. */
    path_preexisted = fs_is_directory(local_path);
    if (path_preexisted) {
        switch (fs_directory_emptiness(local_path, NULL, NULL)) {
            case FS_DIR_EMPTY:
                break;
            case FS_DIR_OCCUPIED:
                err = error_create(
                    ERR_EXISTS, "'%s' exists and is not an empty directory",
                    local_path
                );
                goto cleanup;
            case FS_DIR_UNREADABLE:
                err = error_create(ERR_FS, "Cannot read '%s'", local_path);
                goto cleanup;
        }
    }

    /* The store: bare, declared dotta's from birth, with the remote it came from.
     * Everything from here is the rollback's to undo. */
    err = gitops_init_repository(&repo, local_path);
    if (err) goto cleanup;
    clone_landed = true;

    err = repo_declare_store(repo);
    if (err) goto cleanup;

    git_remote *origin = NULL;
    int rc = git_remote_create(&origin, repo, "origin", opts->url);
    if (rc < 0) {
        err = error_git(rc, "Cannot add remote 'origin'");
        goto cleanup;
    }
    git_remote_free(origin);

    /* The remote, met once (sys/remote.h): its refusal names the act and the
     * remote, under the section that printed the URL; the URL goes in no sentence,
     * since one may carry a password. */
    err = remote_open(repo, "origin", commit_action_word(COMMIT_ACTION_CLONE), out, &remote);
    if (err) goto cleanup;

    /* Identity gate, off the advertisement and before any download.
     * refs/dotta/epoch is the one unconditional, synced dotta artifact, so a
     * remote that does not advertise it is not a dotta repository: refuse before
     * any local materialization below (the objects, the record, the local branches,
     * the baseline). The ref also carries the repository's epoch; without it,
     * every encrypted blob is undecryptable. The verdict is the reconcile's own,
     * over a store that holds no epoch: the adopt, wherever the remote advertises
     * one (infra/epoch.h epoch_resolve). */
    epoch_decision_t decision;
    err = epoch_resolve(repo, remote, &decision);
    if (err) goto cleanup;
    if (git_oid_is_zero(&decision.advertised)) {
        /* Split the diagnostic: an empty remote holds nothing to clone, and a
         * ref-bearing one is not dotta's until a machine that holds the repository
         * syncs to it — the one way to the ref the fact cannot imply */
        if (remote_branches(remote)->count == 0) {
            err = error_create(ERR_NOT_FOUND, "Remote is empty: nothing to clone");
        } else {
            err = error_create(
                ERR_NOT_FOUND, "Remote is not a dotta repository: it does not "
                "advertise '%s'; a sync from a machine that holds the repository "
                "establishes it", EPOCH_REF
            );
        }
        goto cleanup;
    }

    /* One fetch, with progress: every branch the remote advertises, each landing
     * as a remote-tracking ref, and the epoch, its objects for the adopt to judge.
     * No local branch is made here — that is each arm's, for the names it chose
     * off the advertisement. */
    err = remote_fetch(remote, remote_branches(remote), EPOCH_REF, NULL);
    if (err) goto cleanup;

    /* The epoch, installed once its commit is proved (infra/epoch.h epoch_adopt):
     * one it could not adopt installs nothing, so no garbage ref persists. The
     * advertised ref establishes identity (the gate above), but its payload is
     * a crypto concern: warn-and-continue, a plaintext clone is still fine, only
     * encryption is unavailable until a valid epoch arrives — which a sync brings
     * from the remote, and never an init here, which mints one the remote's would
     * not reconcile with, or refuses over the ciphertext this clone just
     * fetched. */
    err = epoch_adopt(repo, &decision, "origin", COMMIT_ACTION_CLONE);
    if (error_code(err) == ERR_CRYPTO) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL,
            "%s; encryption operations fail until a valid epoch is fetched",
            error_line(err)
        );
        /* Said: the error is dropped here, so the arms below meet a clone with
         * no failure in hand rather than one the next assignment overwrites */
        err = NULL;
    }

    /* Any other failure is the install's own, naming the act and the remote */
    if (err) goto cleanup;

    /* Determine which profiles to fetch */
    string_array_t fetched_profiles;
    string_array_init(&fetched_profiles, ctx->arena, 0);

    if (opts->profiles && opts->profile_count > 0) {
        /* Explicit profile management: the names the line gave, each once — a
         * name given twice is one profile, kept where it was first given, as
         * the scope takes it (core/scope.h scope_build) */
        string_array_t specified;
        string_array_init(&specified, ctx->arena, opts->profile_count);
        for (size_t i = 0; i < opts->profile_count; i++) {
            if (string_array_contains(&specified, opts->profiles[i])) continue;
            string_array_push(&specified, opts->profiles[i]);
        }

        land_profiles(
            repo, "origin", specified.entries, specified.count, out, &fetched_profiles
        );

        if (fetched_profiles.count > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Fetched %zu of %zu specified profile%s",
                fetched_profiles.count, specified.count, specified.count == 1 ? "" : "s"
            );
        } else {
            output_summary(out, OUTPUT_NORMAL, "No profiles were fetched");
        }

    } else if (opts->all_profiles) {
        /* Hub mode: every branch the remote advertised, which the one fetch
         * brought, made local */
        const string_array_t *remote_names = remote_branches(remote);
        land_profiles(
            repo, "origin", remote_names->entries, remote_names->count, out,
            &fetched_profiles
        );

        /* Every fetched profile, seeded in the convention's order: the remote's
         * listing has none of its own, and initialize_state enables in the order
         * this list has. Named profiles (-p) keep the order typed; detection
         * sorts its own answer. */
        profile_order(&fetched_profiles);

        if (fetched_profiles.count > 0) {
            output_success(
                out, OUTPUT_NORMAL, "Fetched %zu profile%s",
                fetched_profiles.count, fetched_profiles.count == 1 ? "" : "s"
            );
        } else {
            output_summary(out, OUTPUT_NORMAL, "No profiles were fetched");
        }

    } else {
        /* Default: auto-detect profiles for this machine */
        output_section(
            out, OUTPUT_NORMAL, "Auto-detecting profiles for this system"
        );

        /* Name-based detection against every branch the remote advertised, which
         * the one fetch brought */
        const string_array_t *remote_names = remote_branches(remote);
        string_array_t detected_profiles = profile_detect(ctx->arena, remote_names);

        if (detected_profiles.count > 0) {
            /* Show detected profiles */
            for (size_t i = 0; i < detected_profiles.count; i++) {
                output_info(out, OUTPUT_NORMAL, "  • %s", detected_profiles.entries[i]);
            }

            /* Make the detected profiles local */
            land_profiles(
                repo, "origin", detected_profiles.entries, detected_profiles.count,
                out, &fetched_profiles
            );

            if (fetched_profiles.count > 0) {
                output_success(
                    out, OUTPUT_NORMAL, "Fetched %zu profile%s",
                    fetched_profiles.count, fetched_profiles.count == 1 ? "" : "s"
                );
            } else {
                output_summary(out, OUTPUT_NORMAL, "No profiles were fetched");
            }

        } else {
            /* No profiles detected, so none was fetched: the remote's profiles
             * listed as guidance, under the title profile list gives the remote's
             * not fetched here (cmds/profile.c profile_list), with the two verbs
             * that take one — none is here yet, and enable refuses a profile
             * whose branch is not (cmds/profile.c profile_enable) */
            output_warning(out, OUTPUT_NORMAL, "No profiles auto-detected for this system");
            if (remote_names->count > 0) {
                output_section(out, OUTPUT_NORMAL, "Remote (not fetched)");
                for (size_t i = 0; i < remote_names->count; i++) {
                    output_info(out, OUTPUT_NORMAL, "  • %s", remote_names->entries[i]);
                }
                output_gap(out, OUTPUT_NORMAL);
                output_hint(
                    out, OUTPUT_NORMAL,
                    "Run 'dotta profile fetch <name>', then 'dotta profile enable <name>'"
                );
            }
        }
    }

    /* The profiles to enable: every fetched one whose claims this machine can
     * place. A profile that needs a target is enabled only with one, and clone
     * cannot take one (enable's --target names a single profile): it is left
     * fetched and disabled, named here with the command that enables it. The
     * answer is the profile's own — the labels its walk shows, asked of a table
     * with no binding (core/profiles.h profile_needs_target) — and its failures
     * are the clone's: a tree Git cannot read, or a sheet this build cannot,
     * fails the clone whole and rolls the store back, as the build in
     * initialize_state did for a portable profile and now does for every one. */
    string_array_t to_enable;
    string_array_init(&to_enable, ctx->arena, 0);
    for (size_t i = 0; i < fetched_profiles.count; i++) {
        const char *name = fetched_profiles.entries[i];
        profile_t *profile = NULL;
        bool needs_target = false;
        err = profile_load(repo, name, &profile);
        if (!err) err = profile_needs_target(profile, &needs_target);
        profile_free(profile);
        if (err) goto cleanup;
        if (needs_target) {
            output_gap(out, OUTPUT_NORMAL);
            output_warning(
                out, OUTPUT_NORMAL,
                "Profile '%s' holds custom/ paths and needs a target here; "
                "not enabled", name
            );
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta profile enable %s --target /path' after setup", name
            );
            continue;
        }
        string_array_push(&to_enable, name);
    }

    err = initialize_state(repo, ctx->arena, &to_enable, out);
    if (err) goto cleanup;

    /* Seed the baseline .dottaignore at its own ref with the default patterns.
     *
     * The baseline is this machine's and never travels (core/ignore.h) — the
     * clone fetched branches and the epoch — so a cloned machine starts without
     * one. Seeding here gives every store the same visible, editable starting
     * point that `dotta init` creates — and ensures the safety defaults are applied
     * via the baseline path rather than only through the compiled fallback.
     *
     * Seeded once: a ref that already stands is left alone. */
    err = ignore_seed_baseline(repo, COMMIT_ACTION_CLONE);
    if (err) goto cleanup;

    /* Bootstrap detection and execution.
     *
     * Single-pass filter: walk fetched_profiles once, collect those with a
     * .bootstrap script into `bootstrap_found`, then display, prompt, and
     * (conditionally) fire; what the run did is its receipt. */
    string_array_t bootstrap_found;
    string_array_init(&bootstrap_found, ctx->arena, 0);
    bool run_bootstrap = false;
    bootstrap_receipt_t bootstrap = { 0 };

    /* Check bootstrap scripts in all fetched profiles */
    if (opts->bootstrap_mode != CLONE_BOOTSTRAP_SKIP &&
        fetched_profiles.count > 0) {
        /* Check if any fetched profiles have bootstrap scripts */
        for (size_t i = 0; i < fetched_profiles.count; i++) {
            const char *profile = fetched_profiles.entries[i];
            if (!bootstrap_exists(repo, profile)) continue;
            string_array_push(&bootstrap_found, profile);
        }

        if (bootstrap_found.count > 0) {
            /* The scripts found, under the title every listing of them takes
             * (utils/bootstrap.h bootstrap_spec_t) */
            output_section(out, OUTPUT_NORMAL, "Found bootstrap scripts");
            for (size_t i = 0; i < bootstrap_found.count; i++) {
                output_print(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} %s/%s\n",
                    bootstrap_found.entries[i], BOOTSTRAP_SCRIPT_NAME
                );
            }

            /* Determine if we should run bootstrap */
            if (opts->bootstrap_mode == CLONE_BOOTSTRAP_FORCE) {
                /* --bootstrap flag set, run automatically */
                run_bootstrap = true;
            } else if (opts->verbosity != DOTTA_VERBOSITY_QUIET) {
                /* Prompt user. A clone told -q asks nothing and runs nothing:
                 * read off the flag, never the run's level, since a question is
                 * not output a level gates (base/output.h output_ask) and a
                 * configured quiet never declined it. The scripts are an extra
                 * the clone stands without, so no answer leaves them unrun as a
                 * decline does, and says so with no way on: the hint below names
                 * 'dotta bootstrap' wherever a script was left unrun
                 * (bootstrap_owed). */
                switch (output_ask(out, false, "Execute bootstrap scripts?")) {
                    case OUTPUT_ANSWER_YES:
                        run_bootstrap = true;
                        break;
                    case OUTPUT_ANSWER_NO:
                        break;
                    case OUTPUT_ANSWER_NONE:
                        output_summary(
                            out, OUTPUT_NORMAL, "Bootstrap scripts not run: no answer was read"
                        );
                        break;
                }
            }
        }
    }

    /* Execute bootstrap if requested: the scripts the section above listed —
     * the consent is asked only where one was found, so run_bootstrap implies
     * one */
    if (run_bootstrap) {
        bootstrap_spec_t spec = {
            .config        = config,
            .repo          = repo,
            .repo_dir      = local_path,
            .profiles      = &bootstrap_found,
            .dry_run       = false,
            .stop_on_error = true,
        };
        bootstrap = bootstrap_fire(out, &spec);
    }

    /* Success - print messages before cleanup */
    output_success(out, OUTPUT_NORMAL, "Dotta repository cloned successfully");

    /* Non-fatal — the clone itself succeeded, and the exit code is the clone's.
     * What the clone may not claim is that the bootstrap finished: a script that
     * failed stopped the run on its row, and the closing line names where, in
     * the words cmd_bootstrap's refusal says it in. */
    if (run_bootstrap) {
        if (bootstrap.stopped) {
            output_warning(
                out, OUTPUT_NORMAL, "Bootstrap stopped at profile '%s'", bootstrap.stopped
            );
        } else {
            output_success(out, OUTPUT_NORMAL, "Bootstrap complete");
        }
    }

    /* A repository outside the configured location is one no later command will
     * find: every one of them resolves that location and stops there, so the
     * next `dotta status` would answer "No dotta repository found... Run 'dotta
     * init'" about the repository this run just cloned. */
    if (elsewhere) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL, "dotta looks for its repository at %s", elsewhere
        );
        output_hint(
            out, OUTPUT_NORMAL, "Run 'export DOTTA_REPO_DIR=%s', or set core.repo_dir in "
            "the config file, to use the one just cloned", local_path
        );
    }

    /* The steps that hold, and only those, in the one line they make: the scripts
     * a run did not finish — declined, or stopped at a failure, which `dotta
     * bootstrap` runs again once its reason is fixed (cmds/clone.h) — and the
     * apply that lands what the clone enabled, a clone writing no file of its
     * own */
    const bool bootstrap_owed =
        bootstrap_found.count > 0 && (!run_bootstrap || bootstrap.stopped);
    if (bootstrap_owed && to_enable.count > 0) {
        output_gap(out, OUTPUT_NORMAL);
        output_hint(
            out, OUTPUT_NORMAL, "Run 'dotta bootstrap', then 'dotta apply' to bring the "
            "workspace in line with the enabled profiles"
        );
    } else if (bootstrap_owed) {
        output_gap(out, OUTPUT_NORMAL);
        output_hint(out, OUTPUT_NORMAL, "Run 'dotta bootstrap' to run the bootstrap scripts");
    } else if (to_enable.count > 0) {
        output_gap(out, OUTPUT_NORMAL);
        output_hint(
            out, OUTPUT_NORMAL,
            "Run 'dotta apply' to bring the workspace in line with the enabled profiles"
        );
    }

cleanup:
    /* The remote first, which borrows the store: its free commits the credential
     * helper's verdict (sys/remote.h remote_free) */
    remote_free(remote);
    if (repo) {
        gitops_close_repository(repo);
    }

    /* All-or-nothing: a fatal error after the store landed must not leave a
     * half-initialized repository that blocks the retry (the emptiness test above
     * refuses a non-empty directory). Runs after the repo handle is closed so
     * nothing holds the directory open. */
    if (err && clone_landed) {
        rollback_clone_dir(ctx, local_path, path_preexisted);
    }

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Mutual exclusion: `--all` and `-p/--profile` cannot both constrain the fetch
 * set. Everything else — the URL required, the path optional — is the rows'.
 */
static error_t clone_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_clone_options_t *o = opts_v;

    if (o->all_profiles && o->profile_count > 0) {
        return error_create(
            ERR_INVALID_ARG,
            "--all and --profile are mutually exclusive"
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor: the local path, a directory, once the URL is
 * given. A `-p` value names a profile on a remote not yet cloned — nothing to
 * offer.
 */
static args_want_t clone_complete(
    const void *ctx, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) ctx;
    (void) out;
    const cmd_clone_options_t *o = opts_v;

    if (at->value_of != NULL) return ARGS_WANT_NONE;
    return o->url != NULL && o->path == NULL ? ARGS_WANT_DIRS : ARGS_WANT_NONE;
}

static error_t clone_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_clone(ctx, (const cmd_clone_options_t *) opts_v);
}

static const args_opt_t clone_opts[] = {
    ARGS_GROUP("Options:"),
    /* ARGS_APPEND binds one value per occurrence: `-p a -p b`, never `-p a b`. */
    ARGS_APPEND(
        "p profile",          "<name>",
        cmd_clone_options_t,  profiles,       profile_count,
        "Fetch specific profile(s) (repeatable)"
    ),
    ARGS_FLAG(
        "all",
        cmd_clone_options_t,  all_profiles,
        "Fetch every remote profile (hub/backup workflow)"
    ),
    ARGS_FLAG_SET(
        "bootstrap",
        cmd_clone_options_t,  bootstrap_mode,
        CLONE_BOOTSTRAP_FORCE,
        "Run bootstrap scripts without prompting"
    ),
    ARGS_FLAG_SET(
        "no-bootstrap",
        cmd_clone_options_t,  bootstrap_mode, CLONE_BOOTSTRAP_SKIP,
        "Skip bootstrap scripts entirely"
    ),
    ARGS_FLAG_SET(
        "q quiet",
        cmd_clone_options_t,  verbosity,      DOTTA_VERBOSITY_QUIET,
        "Suppress output"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_clone_options_t,  verbosity,      DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "<url>",
        cmd_clone_options_t,  url,            1,
        "Repository to clone"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "[path]",
        cmd_clone_options_t,  path,           0,
        "Local directory (default: this machine's repository location)"
    ),
    ARGS_END,
};

const args_command_t spec_clone = {
    .name        = "clone",
    .summary     = "Clone an existing dotta repository",
    .usage       = "%s clone [options] <url> [path]",
    .description =
        "Profile Selection:\n"
        "  (default)       Auto-detect profiles for this system\n"
        "                  (global, <os>, hosts/<hostname> and variants).\n"
        "  --all           Hub mode: fetch every remote profile.\n"
        "  -p <name>       Fetch specific profiles explicitly (repeatable).\n",
    .notes       =
        "Profile Behavior:\n"
        "  Fetched profiles are enabled automatically. Run '%s profile\n"
        "  list' to inspect enabled vs available profiles, and '%s\n"
        "  profile fetch <name>', then '%s profile enable <name>', to\n"
        "  add one later.\n",
    .examples    =
        "  %s clone git@github.com:user/dotfiles.git    # Auto-detect profiles\n"
        "  %s clone <url> --all                         # Hub mode\n"
        "  %s clone <url> -p global -p darwin           # Explicit profiles\n"
        "  %s clone <url> --bootstrap                   # Run bootstrap scripts\n",
    .epilogue    =
        "Next steps:\n"
        "  %s profile list             # View enabled profiles\n"
        "  %s profile enable <name>    # Enable additional profiles\n"
        "  %s bootstrap                # Run bootstrap scripts manually\n"
        "  %s apply                    # Deploy profiles to the filesystem\n",
    .opts_size   = sizeof(cmd_clone_options_t),
    .opts        = clone_opts,
    .post_parse  = clone_post_parse,
    .complete    = clone_complete,
    .dispatch    = clone_dispatch,
};
