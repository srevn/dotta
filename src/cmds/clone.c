/**
 * clone.c - Clone dotta repository implementation
 *
 * The clone is init with a remote: the bare store made and declared (utils/repo.h),
 * the remote added, one fetch of everything it has, the epoch taken as the identity
 * gate, and the chosen profiles made local from what landed. No `git_clone`:
 * that call creates a local branch for the remote's HEAD whatever was asked for,
 * and dotta's store has no branch nobody asked for.
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
#include <stdlib.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/epoch.h"
#include "sys/bootstrap.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/bootstrap.h"
#include "utils/repo.h"

/**
 * Make the chosen profiles local
 *
 * The one fetch has run (gitops_fetch_remote): every branch the remote has stands
 * under refs/remotes/<remote>. Each chosen name becomes a local branch at that
 * commit; a name the remote does not have is warned about by name and skipped,
 * so a `-p` typo costs one profile and not the clone.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (typically "origin")
 * @param profiles Array of profile names to make local
 * @param count Number of profiles
 * @param out Output context for messages
 * @param landed_count Output: number made local (can be NULL)
 * @param landed Optional: array to populate with the names made local (can be NULL)
 * @return Error or NULL on success
 */
static error_t *land_profiles(
    git_repository *repo,
    const char *remote_name,
    char **profiles,
    size_t count,
    output_t *out,
    size_t *landed_count,
    string_array_t *landed
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    size_t local_count = 0;
    error_t *err = NULL;

    for (size_t i = 0; i < count; i++) {
        const char *profile = profiles[i];

        /* The local branch: created at the remote's commit, or already here (the
         * same name given twice) and left where it stands */
        err = upstream_ensure_tracking_branch(repo, remote_name, profile);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to create local branch '%s': %s",
                profile, error_message(err)
            );
            error_free(err);
            continue;
        }
        local_count++;

        /* Add to the landed names array if provided */
        if (landed) {
            string_array_push(landed, profile);
        }
    }

    if (landed_count) {
        *landed_count = local_count;
    }

    return NULL;
}

/**
 * Make every remote branch local (hub mode)
 *
 * @param repo Repository
 * @param remote_name Remote name
 * @param out Output context
 * @param landed Output: the profile names made local
 * @return Error or NULL on success
 */
static error_t *land_all_profiles(
    git_repository *repo,
    const char *remote_name,
    output_t *out,
    string_array_t **landed
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    CHECK_NULL(landed);

    output_section(out, OUTPUT_NORMAL, "Fetching all remote profiles");

    /* Every branch the one fetch brought */
    string_array_t *all_branches = NULL;
    error_t *err = gitops_list_remote_tracking(
        repo, remote_name, &all_branches
    );
    if (err) {
        return error_wrap(
            err, "Failed to list remote branches"
        );
    }

    /* Create array for the profiles made local */
    string_array_t *successful = string_array_new(0);
    if (!successful) {
        string_array_free(all_branches);
        return ERROR(
            ERR_MEMORY,
            "Failed to create fetched profiles array"
        );
    }

    /* Create local branches */
    size_t fetched_count = 0;
    err = land_profiles(
        repo, remote_name, all_branches->items, all_branches->count,
        out, &fetched_count, successful
    );

    string_array_free(all_branches);

    if (err) {
        string_array_free(successful);
        return err;
    }

    output_success(
        out, OUTPUT_NORMAL, "Fetched %zu profile%s",
        fetched_count, fetched_count == 1 ? "" : "s"
    );

    *landed = successful;

    return NULL;
}

/**
 * Initialize state with the profiles clone enables
 *
 * Creates the database whatever `profiles` holds, enables exactly the names given
 * — the caller decided which fetched profiles this machine can place — and names
 * them when there are any.
 *
 * @param repo Repository
 * @param profiles Profile names to set as enabled (must not be NULL; may be empty)
 * @param out Output context
 * @return Error or NULL on success
 */
static error_t *initialize_state(
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
    error_t *err = state_open(repo, &state);
    if (err) {
        return error_wrap(err, "Failed to initialize state database");
    }

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
     * enabled. */
    if (profiles->count > 0) {
        for (size_t i = 0; i < profiles->count; i++) {
            err = state_enable_profile(state, profiles->items[i], NULL);
            if (err) {
                state_free(state);
                return error_wrap(
                    err, "Failed to enable profile '%s'", profiles->items[i]
                );
            }
        }

        manifest_t *view = NULL;
        err = manifest_build(repo, state, arena, &view);
        if (err) {
            state_free(state);
            return err;
        }
        manifest_free(view);
    }

    /* Commit transaction */
    err = state_save(state);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to save state");
    }

    state_free(state);

    /* The names enabled, when there are any: a run that enabled nothing said
     * why per profile above, and has no list to print. */
    if (profiles->count > 0) {
        char profiles_str[1024] = { 0 };
        size_t offset = 0;
        for (size_t i = 0; i < profiles->count && offset < sizeof(profiles_str) - 1; i++) {
            int written = snprintf(
                profiles_str + offset, sizeof(profiles_str) - offset,
                "%s%s", profiles->items[i], (i < profiles->count - 1) ? ", " : ""
            );
            if (written > 0) offset += written;
        }

        output_success(
            out, OUTPUT_NORMAL, "Initialized enabled profiles: %s", profiles_str
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
    const char *path,
    bool path_preexisted,
    output_t *out
) {
    error_t *err = NULL;

    if (path_preexisted) {
        string_array_t *entries = NULL;
        err = fs_list_dir(path, &entries);
        if (!err) {
            for (size_t i = 0; i < entries->count && !err; i++) {
                char *child = NULL;
                err = fs_path_join(path, entries->items[i], &child);
                if (!err) {
                    err = fs_clear_path(child);
                    free(child);
                }
            }
            string_array_free(entries);
        }
    } else {
        err = fs_remove_dir(path, true);
    }

    if (err) {
        output_warning(
            out, OUTPUT_NORMAL, "Failed to remove partial clone at %s: %s",
            path, error_message(err)
        );
        output_hint(out, OUTPUT_NORMAL, "Remove it manually before retrying");
        error_free(err);
        return;
    }

    output_info(out, OUTPUT_NORMAL, "Rolled back partial clone at %s", path);
}

/**
 * Clone command implementation
 */
error_t *cmd_clone(const dotta_ctx_t *ctx, const cmd_clone_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->url);

    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    error_t *err = NULL;
    git_repository *repo = NULL;
    char *local_path = NULL;
    char *elsewhere = NULL;
    bool path_preexisted = false;
    bool clone_landed = false;
    transfer_context_t *xfer = NULL;
    string_array_t *fetched_profiles = NULL;
    string_array_t *detected_profiles = NULL;
    string_array_t to_enable STRING_ARRAY_AUTO = { 0 };
    string_array_t bootstrap_found STRING_ARRAY_AUTO = { 0 };

    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    } else if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Where the repository goes: the positional when one was given, this machine's
     * configured location otherwise — one answer, expanded, absolute and with
     * its parents made (utils/repo.h). Absolute matters twice over here: the
     * bootstrap below hands it to a script as $DOTTA_REPO_DIR, and the rollback
     * removes it. */
    err = repo_create_target(config, opts->path, &local_path, &elsewhere);
    if (err) goto cleanup;

    output_section(out, OUTPUT_NORMAL, "Cloning dotta repository");
    output_info(out, OUTPUT_NORMAL, "  URL: %s", opts->url);
    output_info(out, OUTPUT_NORMAL, "  Path: %s", local_path);

    /* Create transfer context for progress reporting and credentials */
    transfer_options_t xfer_opts = {
        .output = out,
        .url    = opts->url,
    };
    err = transfer_context_create(&xfer_opts, &xfer);
    if (err) goto cleanup;

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
                err = ERROR(
                    ERR_EXISTS, "'%s' exists and is not an empty directory",
                    local_path
                );
                goto cleanup;
            case FS_DIR_UNREADABLE:
                err = ERROR(ERR_FS, "Cannot read '%s'", local_path);
                goto cleanup;
        }
    }

    /* The store: bare, declared dotta's from birth, with the remote it came from.
     * Everything from here is the rollback's to undo. */
    err = gitops_init_repository(&repo, local_path);
    if (err) {
        err = error_wrap(err, "Failed to create the repository");
        goto cleanup;
    }
    clone_landed = true;

    err = repo_declare_store(repo);
    if (err) goto cleanup;

    git_remote *remote = NULL;
    int git_err = git_remote_create(&remote, repo, "origin", opts->url);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }
    git_remote_free(remote);

    /* One fetch of everything the remote has, with progress: every branch lands
     * as a remote-tracking ref, and the profile arms below read them from there.
     * No local branch is made here — that is each arm's, for the names it chose. */
    err = gitops_fetch_remote(repo, "origin", xfer);
    if (err) {
        err = error_wrap(err, "Failed to clone repository");
        goto cleanup;
    }

    /* Identity gate + epoch acquisition. refs/dotta/epoch is the one unconditional,
     * synced dotta artifact — the fetch above does not carry it, the default
     * refspec covers refs/heads alone — so a remote that does not advertise it
     * is not a dotta repository: refuse before any local materialization below
     * (the record, the local branches, the baseline). The ref also carries the
     * repository's epoch; without it, every encrypted blob is undecryptable. */
    err = epoch_fetch(repo, "origin", xfer, NULL);
    if (err) {
        if (err->code == ERR_NOT_FOUND) {
            /* Split the diagnostic: an empty remote is a publish-first problem,
             * a ref-bearing one is simply not dotta's. On a listing failure fall
             * through to the foreign diagnostic. */
            bool remote_empty = false;
            string_array_t *remote_refs = NULL;
            error_t *list_err = gitops_list_remote_tracking(
                repo, "origin", &remote_refs
            );
            if (list_err) {
                error_free(list_err);
            } else {
                remote_empty = (remote_refs->count == 0);
                string_array_free(remote_refs);
            }

            error_free(err);

            if (remote_empty) {
                err = ERROR(
                    ERR_NOT_FOUND,
                    "Remote is empty - nothing to clone\n\n"
                    "To publish a new dotta repository:\n"
                    "  dotta init\n"
                    "  dotta remote add origin <url>\n"
                    "  dotta sync"
                );
            } else {
                err = ERROR(
                    ERR_NOT_FOUND,
                    "Remote is not a dotta repository ('%s' not advertised)\n\n"
                    "Check the URL. If this remote should be one, run "
                    "'dotta sync' from a machine that has the repository "
                    "to establish the ref.",
                    EPOCH_REF
                );
            }
            goto cleanup;
        } else if (err->code == ERR_CRYPTO) {
            /* Malformed remote epoch — epoch_fetch installs only what it proved,
             * so no garbage ref persists. The advertised ref establishes identity
             * (the gate above), but its payload is a crypto concern:
             * warn-and-continue, a plaintext clone is still fine, only encryption
             * is unavailable until a valid epoch arrives. */
            output_warning(
                out, OUTPUT_NORMAL,
                "%s. Encryption operations will fail until a valid epoch "
                "is fetched or 'dotta init' is run locally.",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            err = error_wrap(err, "Failed to fetch repository epoch");
            goto cleanup;
        }
    }

    /* Determine which profiles to fetch */
    fetched_profiles = string_array_new(0);
    if (!fetched_profiles) {
        err = ERROR(ERR_MEMORY, "Failed to create profile array");
        goto cleanup;
    }

    if (opts->profiles && opts->profile_count > 0) {
        /* Explicit profile management */
        output_section(out, OUTPUT_NORMAL, "Fetching specified profiles");

        size_t fetched_count = 0;
        err = land_profiles(
            repo, "origin", opts->profiles, opts->profile_count,
            out, &fetched_count, fetched_profiles
        );

        if (err) {
            output_error(
                out, "Failed to fetch profiles: %s",
                error_message(err)
            );
            /* Continue - some profiles may have been fetched */
            error_free(err);
            err = NULL;
        }

        output_success(
            out, OUTPUT_NORMAL, "Fetched %zu of %zu specified profile%s",
            fetched_count, opts->profile_count, opts->profile_count == 1 ? "" : "s"
        );

    } else if (opts->fetch_all) {
        /* Hub mode - fetch all profiles */
        string_array_t *all_profiles = NULL;
        err = land_all_profiles(repo, "origin", out, &all_profiles);

        if (err) {
            output_error(
                out, "Failed to fetch all profiles: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            /* Every fetched profile, seeded in the convention's order: the remote's
             * listing has none of its own, and initialize_state enables in the
             * order this list has. Named profiles (-p) keep the order typed;
             * detection sorts its own answer. */
            profile_order(all_profiles);
            string_array_free(fetched_profiles);
            fetched_profiles = all_profiles;
        }

    } else {
        /* Default: auto-detect profiles for this machine */
        output_section(
            out, OUTPUT_NORMAL, "Auto-detecting profiles for this system"
        );

        /* Every branch the one fetch brought */
        string_array_t *remote_branches = NULL;
        err = gitops_list_remote_tracking(repo, "origin", &remote_branches);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to list remote branches: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
            remote_branches = NULL;
        }

        /* Name-based detection against remote branches */
        if (remote_branches) {
            err = profile_detect(remote_branches, &detected_profiles);
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to detect profiles: %s",
                    error_message(err)
                );
                error_free(err);
                err = NULL;
            }
        }

        if (detected_profiles && detected_profiles->count > 0) {
            /* Show detected profiles */
            for (size_t i = 0; i < detected_profiles->count; i++) {
                output_info(out, OUTPUT_NORMAL, "  • %s", detected_profiles->items[i]);
            }
            output_gap(out, OUTPUT_NORMAL);

            /* Make the detected profiles local */
            size_t fetched_count = 0;
            err = land_profiles(
                repo, "origin", detected_profiles->items, detected_profiles->count,
                out, &fetched_count, fetched_profiles
            );
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Some profiles failed to fetch: %s",
                    error_message(err)
                );
                error_free(err);
                err = NULL;
            }

            if (fetched_count > 0) {
                output_success(
                    out, OUTPUT_NORMAL, "Fetched %zu profile%s",
                    fetched_count, fetched_count == 1 ? "" : "s"
                );
            }

        } else {
            /* No profiles detected — show available remote branches as guidance */
            output_warning(out, OUTPUT_NORMAL, "No profiles auto-detected for this system");
            if (remote_branches && remote_branches->count > 0) {
                output_section(out, OUTPUT_NORMAL, "Available remote profiles");
                for (size_t i = 0; i < remote_branches->count; i++) {
                    output_info(out, OUTPUT_NORMAL, "  • %s", remote_branches->items[i]);
                }
                output_gap(out, OUTPUT_NORMAL);
            }
            output_info(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>' after setup");
        }

        string_array_free(remote_branches);
    }

    /* The profiles to enable: every fetched one whose claims this machine can
     * place. A profile that needs a target is enabled only with one, and clone
     * cannot take one (enable's --target names a single profile): it is left
     * fetched and disabled, named here with the command that enables it. The
     * answer is the view's over the branch alone (core/profiles.h
     * profile_needs_target), and its failures are the clone's: a tree Git cannot
     * read, or a sheet this build cannot, fails the clone whole and rolls the
     * store back — as the build in initialize_state already did for a portable
     * branch, and now for every fetched one. */
    for (size_t i = 0; i < fetched_profiles->count; i++) {
        const char *profile = fetched_profiles->items[i];
        bool needs_target = false;
        err = profile_needs_target(repo, profile, &needs_target);
        if (err) goto cleanup;
        if (needs_target) {
            output_warning(
                out, OUTPUT_NORMAL,
                "Profile '%s' holds custom/ paths and needs a target here; "
                "not enabled", profile
            );
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta profile enable %s --target /path' after setup", profile
            );
            continue;
        }
        err = string_array_push(&to_enable, profile);
        if (err) goto cleanup;
    }

    if (fetched_profiles->count == 0) {
        output_warning(out, OUTPUT_NORMAL, "No profiles were fetched");
    }

    err = initialize_state(repo, ctx->arena, &to_enable, out);
    if (err) {
        err = error_wrap(err, "Failed to initialize state");
        goto cleanup;
    }

    /* Seed the baseline .dottaignore at its own ref with the default patterns.
     *
     * The baseline is this machine's and never travels (core/ignore.h) — the
     * clone fetched branches and the epoch — so a cloned machine starts without
     * one. Seeding here gives every store the same visible, editable starting
     * point that `dotta init` creates — and ensures the safety defaults are applied
     * via the baseline path rather than only through the compiled fallback.
     *
     * Seeded once: a ref that already stands is left alone. */
    err = ignore_seed_baseline(repo);
    if (err) {
        err = error_wrap(err, "Failed to seed baseline .dottaignore");
        goto cleanup;
    }

    /* Bootstrap detection and execution.
     *
     * Single-pass filter: walk fetched_profiles once, collect those with a
     * .bootstrap script into `bootstrap_found`, then display, prompt, and
     * (conditionally) fire. bootstrap_available is a simple derived flag used
     * by the final "Next steps" hint. */
    bool run_bootstrap = false;
    bool bootstrap_available = false;
    bool bootstrap_failed = false;

    /* Check bootstrap scripts in all fetched profiles */
    if (opts->bootstrap_mode != CLONE_BOOTSTRAP_SKIP &&
        fetched_profiles->count > 0) {
        /* Check if any fetched profiles have bootstrap scripts */
        for (size_t i = 0; i < fetched_profiles->count; i++) {
            const char *profile = fetched_profiles->items[i];
            if (!bootstrap_exists(repo, profile)) continue;
            err = string_array_push(&bootstrap_found, profile);
            if (err) {
                err = error_wrap(
                    err, "Failed to collect bootstrap profiles"
                );
                goto cleanup;
            }
        }

        bootstrap_available = (bootstrap_found.count > 0);

        if (bootstrap_available) {
            output_section(
                out, OUTPUT_NORMAL, "Bootstrap scripts available"
            );
            for (size_t i = 0; i < bootstrap_found.count; i++) {
                output_styled(
                    out, OUTPUT_NORMAL, "  {green}✓{reset} %s/%s\n",
                    bootstrap_found.items[i], BOOTSTRAP_SCRIPT_NAME
                );
            }
            output_gap(out, OUTPUT_NORMAL);

            /* Determine if we should run bootstrap */
            if (opts->bootstrap_mode == CLONE_BOOTSTRAP_FORCE) {
                /* --bootstrap flag set, run automatically */
                run_bootstrap = true;
            } else if (!opts->quiet) {
                /* Prompt user */
                run_bootstrap = output_confirm(
                    out, "Execute bootstrap scripts?", false
                );
            }
        }
    }

    /* Execute bootstrap if requested */
    if (run_bootstrap && bootstrap_found.count > 0) {
        output_gap(out, OUTPUT_NORMAL);
        bootstrap_spec_t spec = {
            .repo          = repo,
            .repo_dir      = local_path,
            .profiles      = &bootstrap_found,
            .dry_run       = false,
            .stop_on_error = true,
        };
        err = bootstrap_fire(out, &spec);
        if (err) {
            output_error(out, "Bootstrap failed: %s", error_message(err));
            error_free(err);
            err = NULL;
            /* Non-fatal — the clone itself succeeded, and the exit code is the
             * clone's. What the clone may not claim is that the bootstrap finished:
             * the closing line reads off this flag, the way cmd_bootstrap reads
             * off its own. */
            bootstrap_failed = true;
        }
    }

    /* Success - print messages before cleanup */
    output_gap(out, OUTPUT_NORMAL);
    output_success(out, OUTPUT_NORMAL, "Dotta repository cloned successfully!");

    if (run_bootstrap) {
        if (bootstrap_failed) {
            output_warning(out, OUTPUT_NORMAL, "Bootstrap completed with errors.");
        } else {
            output_success(out, OUTPUT_NORMAL, "Bootstrap complete!");
        }
    }

    /* A repository outside the configured location is one no later command will
     * find: every one of them resolves that location and stops there, so the
     * next `dotta status` would answer "No dotta repository found... Run 'dotta
     * init'" about the repository this run just cloned. */
    if (elsewhere) {
        output_warning(
            out, OUTPUT_NORMAL, "dotta looks for its repository at %s", elsewhere
        );
        output_hint(out, OUTPUT_NORMAL, "To use the one just cloned, either:");
        output_hintline(out, OUTPUT_NORMAL, "  export DOTTA_REPO_DIR=%s", local_path);
        output_hintline(
            out, OUTPUT_NORMAL, "  or set repo_dir under [core] in the config file"
        );
    }

    output_gap(out, OUTPUT_NORMAL);
    output_hintline(out, OUTPUT_NORMAL, "Next steps:");
    if (!run_bootstrap && bootstrap_available) {
        output_hintline(out, OUTPUT_NORMAL, "  Run bootstrap:  dotta bootstrap");
    }
    output_hintline(out, OUTPUT_NORMAL, "  List profiles:  dotta profile list");
    output_hintline(out, OUTPUT_NORMAL, "  Apply profiles: dotta apply");
    output_hintline(out, OUTPUT_NORMAL, "  View state:     dotta status");

cleanup:
    /* Cleanup resources */
    string_array_free(detected_profiles);
    if (xfer) {
        transfer_context_free(xfer);
    }
    if (fetched_profiles) {
        string_array_free(fetched_profiles);
    }
    if (repo) {
        gitops_close_repository(repo);
    }

    /* All-or-nothing: a fatal error after the store landed must not leave a
     * half-initialized repository that blocks the retry (the emptiness test above
     * refuses a non-empty directory). Runs after the repo handle is closed so
     * nothing holds the directory open. */
    if (err && clone_landed) {
        rollback_clone_dir(local_path, path_preexisted, out);
    }

    free(local_path);
    free(elsewhere);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Mutual exclusion: `--all` and `-p/--profile` cannot both constrain the fetch
 * set. Everything else — the URL required, the path optional — is the rows'.
 */
static error_t *clone_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_clone_options_t *o = opts_v;

    if (o->fetch_all && o->profile_count > 0) {
        return ERROR(
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

static error_t *clone_dispatch(const void *ctx_v, void *opts_v) {
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
        cmd_clone_options_t,  fetch_all,
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
    ARGS_FLAG(
        "q quiet",
        cmd_clone_options_t,  quiet,
        "Suppress output"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_clone_options_t,  verbose,
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
        "  profile enable <name>' to add one later.\n",
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
