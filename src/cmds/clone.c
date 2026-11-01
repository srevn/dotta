/**
 * clone.c - Clone dotta repository implementation
 *
 * The clone is init with a remote: the bare store created and declared
 * (utils/repo.h), the remote added and met once (sys/remote.h) — its advertisement
 * of the epoch the identity gate, and its branches what the profiles are selected
 * off, then one fetch of the selected profiles and of the epoch, the epoch adopted
 * — and the selected profiles made local. The remote's other branches stay there.
 * No `git_clone`: that call fetches every branch the remote has and creates a
 * local branch for the remote's HEAD whatever was asked for
 * (lib/libgit2/src/libgit2/clone.c clone_into), and dotta's store has no branch
 * and no tracking ref nobody asked for.
 *
 * Smart profile management
 * - Auto-detects relevant profiles by default
 * - Fetches and makes local only the detected/specified profiles
 * - Initializes state with those profiles
 * - Supports hub mode (--all) for backup workflows
 */

#include "cmds/clone.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <string.h>

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
#include "utils/bootstrap.h"
#include "utils/repo.h"

/**
 * Select the profiles the clone fetches and lands, off the remote's listing
 *
 * Asked before anything is fetched, of the branches the remote holds now
 * (sys/remote.h remote_branches): the names the line gave (-p), each once, every
 * one the remote does not hold refusing the clone, as git's clone refuses a
 * --branch its remote lacks (lib/git/builtin/clone.c cmd_clone); every branch
 * the remote holds (--all); otherwise the ones this machine layers (core/profiles.h
 * profile_detect). An empty selection says why here, where it is made — a remote
 * holding no profile, or none this machine layers, the remote's then listed —
 * so the receipt says only what landed (cmd_clone).
 *
 * @param opts Clone options (must not be NULL)
 * @param remote_name Remote name (typically "origin")
 * @param remote_names The branches the remote advertises (must not be NULL)
 * @param arena Arena the selection lives in (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @param selection The profiles, each once, in the order they are landed and
 *                  enabled (must not be NULL; set on success)
 * @return Error or NULL on success
 */
static error_t select_profiles(
    const cmd_clone_options_t *opts, const char *remote_name,
    const string_array_t *remote_names, arena_t *arena, output_t *out,
    string_array_t *selection
) {
    CHECK_NULL(opts);
    CHECK_NULL(remote_names);
    CHECK_NULL(arena);
    CHECK_NULL(out);
    CHECK_NULL(selection);

    /* Explicit profile management: the names the line gave, each once — a name
     * given twice is one profile, kept where it was first given, as the scope
     * takes it (core/scope.h scope_build) — and every one the remote does not
     * hold refused together, before anything is fetched, in profile fetch's words
     * (cmds/profile.c profile_fetch): named profiles are fetched whole or not
     * at all. The names the remote does hold are in hand, and the refusal says
     * them. */
    if (opts->profile_count > 0) {
        string_array_t missing;
        string_array_init(selection, arena, opts->profile_count);
        string_array_init(&missing, arena, 0);
        for (size_t i = 0; i < opts->profile_count; i++) {
            const char *name = opts->profiles[i];
            if (string_array_contains(selection, name) ||
                string_array_contains(&missing, name)) {
                continue;
            }

            string_array_push(
                string_array_contains(remote_names, name) ? selection : &missing, name
            );
        }
        if (missing.count > 0) {
            return error_create(
                ERR_NOT_FOUND, "%s '%s' %s not on remote '%s', which holds %s",
                missing.count == 1 ? "Profile" : "Profiles",
                string_array_join(arena, &missing, "', '"),
                missing.count == 1 ? "is" : "are", remote_name,
                remote_names->count > 0
                    ? string_array_join(arena, remote_names, ", ") : "no profiles"
            );
        }
        return NULL;
    }

    /* A remote that holds no profile has none to select, whichever arm asked:
     * said once, in profile fetch --all's words, and the clone lands its epoch
     * alone */
    if (remote_names->count == 0) {
        string_array_init(selection, arena, 0);
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "Remote '%s' holds no profiles", remote_name);
        return NULL;
    }

    /* Hub mode: every branch the remote advertises, seeded in the convention's
     * order: the remote's listing has none of its own, and initialize_state enables
     * in the order the selection has. Named profiles (-p) keep the order typed;
     * detection sorts its own answer. */
    if (opts->all_profiles) {
        string_array_clone(remote_names, arena, selection);
        profile_order(selection);
        return NULL;
    }

    /* Default: the profiles this machine layers, matched by name among the branches
     * the remote advertises; the receipt names the ones it enables (cmd_clone) */
    *selection = profile_detect(arena, remote_names);
    if (selection->count > 0) return NULL;

    /* None detected, so none is fetched: the remote's profiles listed, under
     * the title profile list gives the remote's not fetched here (cmds/profile.c
     * profile_list) */
    output_gap(out, OUTPUT_NORMAL);
    output_warning(out, OUTPUT_NORMAL, "No profiles auto-detected for this system");
    output_section(out, OUTPUT_NORMAL, "Remote (not fetched)");
    for (size_t i = 0; i < remote_names->count; i++) {
        output_info(out, OUTPUT_NORMAL, "  • %s", remote_names->entries[i]);
    }

    return NULL;
}

/**
 * Make the selected profiles local
 *
 * The one fetch has run (sys/remote.h remote_fetch): each selected profile, a
 * branch the remote advertised (select_profiles), has its head's objects here.
 * Each becomes a local branch at that head, as the open listed it; one that cannot
 * is warned about by name and skipped, so one profile costs itself and not the
 * clone. The warnings are one block, beneath whatever stood: its boundary is
 * asked here and paid by the first of them. What landed is the receipt's to say,
 * once nothing can roll the store back (cmd_clone).
 *
 * @param repo Repository (must not be NULL)
 * @param remote The session, its listing the remote's heads (must not be NULL)
 * @param remote_name Remote name (typically "origin")
 * @param selection The profiles to make local, each once (must not be NULL)
 * @param arena Arena the names made local live in (must not be NULL)
 * @param out Output context for messages (must not be NULL)
 * @return The names made local, in the selection's order
 */
static string_array_t land_profiles(
    git_repository *repo, const remote_t *remote, const char *remote_name,
    const string_array_t *selection, arena_t *arena, output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote);
    CHECK_NULL(selection);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    string_array_t landed;
    string_array_init(&landed, arena, selection->count);

    output_gap(out, OUTPUT_NORMAL);
    for (size_t i = 0; i < selection->count; i++) {
        const char *profile = selection->entries[i];

        /* The local branch, created at the remote's head: each name comes once,
         * into a store the clone just made. A name that fails — a remote's branch
         * at a tag or a tree among them — is warned about and skipped, its error
         * dropped, one per such name. */
        char ref[DOTTA_REFNAME_MAX];
        git_oid head;
        error_t err = gitops_branch_refname(ref, sizeof(ref), profile);
        if (!err) {
            remote_advertised(remote, ref, &head);
            err = gitops_create_branch(
                repo, profile, &head, commit_action_word(COMMIT_ACTION_CLONE),
                "created from %s/%s", remote_name, profile
            );
        }
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to create local branch '%s': %s",
                profile, error_line(err)
            );
            continue;
        }

        string_array_push(&landed, profile);
    }

    return landed;
}

/**
 * Initialize state with the profiles clone enables
 *
 * Creates the database whatever `profiles` holds and enables exactly the names
 * given — the caller decided which landed profiles this machine can place, and
 * names them in its receipt.
 *
 * @param repo Repository
 * @param arena Arena the view is built in
 * @param profiles Profile names to set as enabled (must not be NULL; may be empty)
 * @return Error or NULL on success
 */
static error_t initialize_state(
    git_repository *repo, arena_t *arena, const string_array_t *profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(profiles);

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
    return err;
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
 *
 * A removal that worked says nothing: the refusal it unwinds says the clone failed,
 * and a failed clone left nothing, as git's says by its silence
 * (lib/git/builtin/clone.c remove_junk). One that failed names what stands, which
 * the next clone into it refuses by name.
 */
static void rollback_clone_dir(
    const dotta_ctx_t *ctx, const char *path, bool path_preexisted
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

    /* What stands, a block of its own beneath what the clone said before it
     * failed */
    if (err) {
        output_gap(ctx->out, OUTPUT_NORMAL);
        output_warning(
            ctx->out, OUTPUT_NORMAL, "Failed to remove partial clone at %s: %s",
            path, error_line(err)
        );
    }
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

    /* origin's URL, as every later command reads it: one with no ':' is a path
     * to libgit2 (lib/libgit2/src/libgit2/transport.c transport_find_fn), read
     * against the working directory of whichever run reads it, which dotta never
     * moves — so it is stored absolute, as git's clone stores a local path
     * (lib/git/builtin/clone.c cmd_clone, absolute_pathdup) */
    const char *url = opts->url;
    if (!strchr(url, ':')) {
        err = fs_make_absolute(opts->url, ctx->arena, &url);
        if (err) goto cleanup;
    }

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
    int rc = git_remote_create(&origin, repo, "origin", url);
    if (rc < 0) {
        err = error_git(rc, "Cannot add remote 'origin'");
        goto cleanup;
    }
    git_remote_free(origin);

    /* The remote, met once (sys/remote.h). Over the contact and the fetch a
     * progress line, a terminal's alone, as sync's and profile fetch's
     * (base/output.h output_progress): drawn before the open and taken down once
     * the fetch is done, so a refusal or a warning between them stands on a row
     * of its own. The open's refusal names the act and the remote, and no line
     * names the URL, which may carry a password. */
    output_progress(out, OUTPUT_NORMAL, "Fetching from 'origin'...");
    err = remote_open(
        repo, "origin", commit_action_word(COMMIT_ACTION_CLONE), out, &remote
    );
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

    /* The profiles the clone lands, selected off the advertisement before anything
     * is fetched: a name the line gives that the remote lacks refuses the clone
     * here, nothing downloaded */
    string_array_t selection;
    err = select_profiles(
        opts, "origin", remote_branches(remote), ctx->arena, out, &selection
    );
    if (err) goto cleanup;

    /* One fetch, with progress: each selected profile, landing as a remote-tracking
     * ref, and the epoch, its objects for the adopt to judge. The remote's other
     * branches stay there, their names kept by the open for completion's offers
     * (sys/remote.h remote_last_branches) — on a path remote their objects arrive
     * all the same, unnamed (sys/remote.h). No local branch is made here: that
     * is the land's, below. */
    err = remote_fetch(remote, &selection, EPOCH_REF, NULL);
    output_clear_line(out);
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
        /* Said: the error is dropped here, so what follows meets a clone with
         * no failure in hand rather than one the next assignment overwrites */
        err = NULL;
    }

    /* Any other failure is the install's own, naming the act and the remote */
    if (err) goto cleanup;

    /* The selection made local */
    const string_array_t landed = land_profiles(
        repo, remote, "origin", &selection, ctx->arena, out
    );

    /* The profiles to enable: every landed one whose claims this machine can
     * place. A profile that needs a target is enabled only with one, and clone
     * cannot take one (enable's --target names a single profile): it is left
     * fetched and disabled, said in the sentence profile enable refuses it with
     * (cmds/profile.c profile_enable), the command that places it the help's.
     * The answer is the profile's own — the labels its walk shows, asked of a
     * table with no binding (core/profiles.h profile_needs_target) — and its
     * failures are the clone's: a tree Git cannot read, or a sheet this build
     * cannot, fails the clone whole and rolls the store back, as the build in
     * initialize_state did for a portable profile and now does for every one. */
    string_array_t to_enable;
    string_array_init(&to_enable, ctx->arena, 0);
    for (size_t i = 0; i < landed.count; i++) {
        const char *name = landed.entries[i];
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
            continue;
        }
        string_array_push(&to_enable, name);
    }

    err = initialize_state(repo, ctx->arena, &to_enable);
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

    /* The clone's receipt, said once nothing can roll the store back: every failure
     * above unwinds it whole (cleanup), so a line said sooner would tell an act
     * the rollback undoes (base/output.h output_success). What landed, alike
     * whichever arm selected — a selection none of which landed says so beneath
     * its warnings, an empty one said why where it was made — in profile fetch's
     * words; what it enabled, in enable's; the store, as init names it. */
    if (landed.count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Fetched %zu profile%s from '{cyan}%s{reset}'",
            landed.count, landed.count == 1 ? "" : "s", "origin"
        );
    } else if (selection.count > 0) {
        output_summary(out, OUTPUT_NORMAL, "No profiles were fetched");
    }
    if (to_enable.count > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Enabled %s",
            string_array_join(ctx->arena, &to_enable, ", ")
        );
    }
    output_success(out, OUTPUT_NORMAL, "Cloned dotta repository into %s", local_path);

    /* The scripts, a phase of their own past the clone, closed by its outcome
     * (base/output.h output_summary): the landed profiles' that hold one, collected
     * once and listed under the title every listing of them takes
     * (utils/bootstrap.h bootstrap_spec_t), then run where --bootstrap or the
     * user says so. The clone stands either way, its exit code its own
     * (cmds/clone.h). */
    string_array_t bootstrap_found;
    string_array_init(&bootstrap_found, ctx->arena, 0);
    if (opts->bootstrap_mode != CLONE_BOOTSTRAP_SKIP) {
        for (size_t i = 0; i < landed.count; i++) {
            if (bootstrap_exists(repo, landed.entries[i])) {
                string_array_push(&bootstrap_found, landed.entries[i]);
            }
        }
    }

    if (bootstrap_found.count > 0) {
        output_section(out, OUTPUT_NORMAL, "Found bootstrap scripts");
        for (size_t i = 0; i < bootstrap_found.count; i++) {
            output_print(
                out, OUTPUT_NORMAL, "  {green}✓{reset} %s/%s\n",
                bootstrap_found.entries[i], BOOTSTRAP_SCRIPT_NAME
            );
        }

        /* Asked unless --bootstrap answered it. A clone told -q asks nothing
         * and runs nothing: read off the flag, never the run's level, since a
         * question is not output a level gates (base/output.h output_ask) and a
         * configured quiet never declined it. The scripts are an extra the clone
         * stands without, so a decline and no answer each leave them unrun, and
         * say so. */
        bool run_bootstrap = opts->bootstrap_mode == CLONE_BOOTSTRAP_FORCE;
        if (!run_bootstrap && opts->verbosity != DOTTA_VERBOSITY_QUIET) {
            switch (output_ask(out, false, "Execute bootstrap scripts?")) {
                case OUTPUT_ANSWER_YES:
                    run_bootstrap = true;
                    break;
                case OUTPUT_ANSWER_NO:
                    output_summary(out, OUTPUT_NORMAL, "Bootstrap scripts not run");
                    break;
                case OUTPUT_ANSWER_NONE:
                    output_summary(
                        out, OUTPUT_NORMAL,
                        "Bootstrap scripts not run: no answer was read"
                    );
                    break;
            }
        }

        /* What the clone may not claim is that the bootstrap finished: a script
         * that failed stopped the run on its row, and the outcome names where,
         * in the words cmd_bootstrap's refusal says it in, a block of its own
         * beneath the rows as the complete's is */
        if (run_bootstrap) {
            bootstrap_spec_t spec = {
                .config        = config,
                .repo          = repo,
                .repo_dir      = local_path,
                .profiles      = &bootstrap_found,
                .dry_run       = false,
                .stop_on_error = true,
            };
            bootstrap_receipt_t bootstrap = bootstrap_fire(out, &spec);
            if (bootstrap.stopped) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(
                    out, OUTPUT_NORMAL, "Bootstrap stopped at profile '%s'",
                    bootstrap.stopped
                );
            } else {
                output_success(out, OUTPUT_NORMAL, "Bootstrap complete");
            }
        }
    }

    /* A repository outside the configured location is one no later command will
     * find: every one of them resolves that location and stops there, so the
     * next `dotta status` would answer "No dotta repository found at" the
     * configured location, the repository this run just cloned standing elsewhere.
     * Where they look is said; how to point them here, the help's. */
    if (elsewhere) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL, "dotta looks for its repository at %s", elsewhere
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
        "The repository path defaults to $DOTTA_REPO_DIR, then the path\n"
        "configured in config.toml, then the per-user default directory.\n"
        "\n"
        "Profile Selection:\n"
        "  (default)       Auto-detect profiles for this system\n"
        "                  (global, <os>, hosts/<hostname> and variants).\n"
        "  --all           Hub mode: fetch every remote profile.\n"
        "  -p <name>       Fetch specific profiles explicitly (repeatable).\n"
        "                  A name the remote lacks refuses the clone.\n",
    .notes       =
        "Profile Behavior:\n"
        "  Only the selected profiles are fetched. Each is enabled, except\n"
        "  one holding custom/ paths, which needs a target first:\n"
        "  '%s profile enable <name> --target <dir>'.\n"
        "\n"
        "  The remote's other profiles stay on the remote. List them with\n"
        "  '%s profile list --all', and bring one later with\n"
        "  '%s profile fetch <name>' and '%s profile enable <name>'.\n",
    .examples    =
        "  %s clone git@github.com:user/dotfiles.git    # Auto-detect profiles\n"
        "  %s clone <url> --all                         # Hub mode\n"
        "  %s clone <url> -p global -p darwin           # Explicit profiles\n"
        "  %s clone <url> --bootstrap                   # Run bootstrap scripts\n",
    .epilogue    =
        "Next steps:\n"
        "  %s profile list             # View enabled profiles\n"
        "  %s profile fetch <name>     # Fetch another profile\n"
        "  %s bootstrap                # Run bootstrap scripts manually\n"
        "  %s apply                    # Deploy profiles to the filesystem\n",
    .opts_size   = sizeof(cmd_clone_options_t),
    .opts        = clone_opts,
    .post_parse  = clone_post_parse,
    .complete    = clone_complete,
    .dispatch    = clone_dispatch,
};
