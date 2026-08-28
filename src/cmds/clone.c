/**
 * clone.c - Clone dotta repository implementation
 *
 * Smart profile management
 * - Auto-detects relevant profiles by default
 * - Fetches only detected/specified profiles
 * - Initializes state with fetched profiles
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
#include "infra/salt.h"
#include "sys/bootstrap.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/bootstrap.h"
#include "utils/repo.h"

/**
 * Fetch profiles and create local tracking branches
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (typically "origin")
 * @param profiles Array of profile names to fetch
 * @param count Number of profiles
 * @param out Output context for messages
 * @param cred_ctx Credential context
 * @param fetched_count Output: number successfully fetched (can be NULL)
 * @param fetched_profiles Optional: array to populate with successfully fetched
 *                         names (can be NULL)
 * @return Error or NULL on success
 */
static error_t *fetch_profiles(
    git_repository *repo,
    const char *remote_name,
    char **profiles,
    size_t count,
    output_t *out,
    transfer_context_t *xfer,
    size_t *fetched_count,
    string_array_t *fetched_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    size_t local_count = 0;
    error_t *err = NULL;

    for (size_t i = 0; i < count; i++) {
        const char *profile = profiles[i];

        if (output_is_tty(out)) {
            output_info(out, OUTPUT_NORMAL, "  Fetching %s...", profile);
        }

        /* Fetch the profile branch */
        err = gitops_fetch_branch(repo, remote_name, profile, xfer);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to fetch '%s': %s",
                profile, error_message(err)
            );
            error_free(err);
            continue;
        }

        /* Create local tracking branch if it doesn't already exist */
        bool already_exists = profile_exists(repo, profile);
        if (already_exists) {
            /* Branch already exists (e.g., from git_clone) - skip creation */
            local_count++;
        } else {
            /* Create new local tracking branch */
            err = upstream_create_tracking_branch(
                repo, remote_name, profile
            );
            if (err) {
                output_warning(
                    out, OUTPUT_NORMAL, "Failed to create local branch '%s': %s",
                    profile, error_message(err)
                );
                error_free(err);
                continue;
            }
            local_count++;
        }

        /* Add to fetched names array if provided */
        if (fetched_profiles) {
            string_array_push(fetched_profiles, profile);
        }
    }

    if (fetched_count) {
        *fetched_count = local_count;
    }

    return NULL;
}

/**
 * Fetch all remote branches (hub mode)
 *
 * @param repo Repository
 * @param remote_name Remote name
 * @param out Output context
 * @param xfer Transfer context
 * @param fetched_profiles Output: fetched profile names array
 * @return Error or NULL on success
 */
static error_t *fetch_all_profiles(
    git_repository *repo,
    const char *remote_name,
    output_t *out,
    transfer_context_t *xfer,
    string_array_t **fetched_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    CHECK_NULL(fetched_profiles);

    output_section(out, OUTPUT_NORMAL, "Fetching all remote profiles");

    /* List all remote tracking branches */
    string_array_t *all_branches = NULL;
    error_t *err = gitops_list_remote_tracking(
        repo, remote_name, &all_branches
    );
    if (err) {
        return error_wrap(
            err, "Failed to list remote branches"
        );
    }

    /* Create array for successfully fetched profiles */
    string_array_t *successful = string_array_new(0);
    if (!successful) {
        string_array_free(all_branches);
        return ERROR(
            ERR_MEMORY,
            "Failed to create fetched profiles array"
        );
    }

    /* Fetch and create local branches */
    size_t fetched_count = 0;
    err = fetch_profiles(
        repo, remote_name, all_branches->items, all_branches->count,
        out, xfer, &fetched_count, successful
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

    *fetched_profiles = successful;

    return NULL;
}

/**
 * Initialize state with fetched profiles
 *
 * @param repo Repository
 * @param profiles Profile names to set as enabled (must not be NULL)
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
     * per profile, always with target=NULL: a per-machine target is enable's to
     * bind later, and a custom/-bearing profile's claims are simply held by the
     * build (recorded on the view) until it is.
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

    /* Build profile list string */
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
        out, OUTPUT_NORMAL, "Initialized enabled profiles: %s",
        profiles_str
    );

    return NULL;
}

/**
 * Remove what a failed clone left behind.
 *
 * Clone's entire side-effect surface is the target directory (state DB and branches
 * live under .git/, the seeded .dottaignore in the workdir), so all-or-nothing
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

    /* Track whether the target directory predates the clone (git_clone accepts
     * an existing empty directory): rollback preserves a pre-existing directory
     * and only empties it. */
    path_preexisted = fs_is_directory(local_path);

    /* Clone repository with progress reporting */
    err = gitops_clone(&repo, opts->url, local_path, xfer);
    if (err) {
        err = error_wrap(err, "Failed to clone repository");
        goto cleanup;
    }
    clone_landed = true;

    /* Identity gate + salt acquisition. refs/dotta/salt is the one unconditional,
     * synced dotta artifact (dotta-worktree never leaves the local repo), so a
     * remote that does not advertise it is not a dotta repository — refuse before
     * any local materialization below (state DB, dotta-worktree branch, baseline
     * .dottaignore). The ref also carries the per-repo Argon2id salt; without
     * it, every encrypted blob is undecryptable. */
    err = salt_fetch(repo, "origin", xfer, NULL);
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
                    SALT_REF
                );
            }
            goto cleanup;
        } else if (err->code == ERR_CRYPTO) {
            /* Malformed remote salt — salt_fetch already rolled back, so no garbage
             * ref persists. The advertised ref establishes identity (the gate
             * above), but its payload is a crypto concern: warn-and-continue, a
             * plaintext clone is still fine, only encryption is unavailable until
             * a valid salt arrives. */
            output_warning(
                out, OUTPUT_NORMAL,
                "%s. Encryption operations will fail until a valid salt "
                "is fetched or 'dotta init' is run locally.",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            err = error_wrap(err, "Failed to fetch repository salt");
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
        err = fetch_profiles(
            repo, "origin", opts->profiles, opts->profile_count,
            out, xfer, &fetched_count, fetched_profiles
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
        err = fetch_all_profiles(repo, "origin", out, xfer, &all_profiles);

        if (err) {
            output_error(
                out, "Failed to fetch all profiles: %s",
                error_message(err)
            );
            error_free(err);
            err = NULL;
        } else {
            /* Use all fetched profiles */
            string_array_free(fetched_profiles);
            fetched_profiles = all_profiles;
        }

    } else {
        /* Default: auto-detect profiles for this machine */
        output_section(
            out, OUTPUT_NORMAL, "Auto-detecting profiles for this system"
        );

        /* List all remote tracking branches (available after clone) */
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
            output_newline(out, OUTPUT_NORMAL);

            /* Fetch detected profiles */
            size_t fetched_count = 0;
            err = fetch_profiles(
                repo, "origin", detected_profiles->items, detected_profiles->count,
                out, xfer, &fetched_count, fetched_profiles
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
                output_newline(out, OUTPUT_NORMAL);
            }
            output_info(out, OUTPUT_NORMAL, "Run 'dotta profile enable <name>' after setup");
        }

        string_array_free(remote_branches);
    }

    /* Initialize state with fetched profiles.
     *
     * Profiles with custom/ files need a machine-specific --target to place those
     * claims, and clone cannot take one (enable's --target names a single profile).
     * They are enabled anyway: the build holds the unplaceable claims, status
     * carries the health, and the warning below names the binding verb at the
     * bootstrap moment — a warned-but-whole bootstrap instead of one that silently
     * withholds the profile's home/ rows along with its custom/ ones. */
    if (fetched_profiles->count > 0) {
        for (size_t i = 0; i < fetched_profiles->count; i++) {
            const char *profile = fetched_profiles->items[i];
            bool has_custom = false;

            error_t *check_err = profile_has_custom_files(repo, profile, &has_custom);
            if (check_err) {
                /* Cannot determine — enable it; the health surfaces speak if
                 * its claims turn out unplaceable. */
                error_free(check_err);
                continue;
            }

            if (has_custom) {
                output_warning(
                    out, OUTPUT_NORMAL,
                    "Profile '%s' has custom/ paths that need a deployment target",
                    profile
                );
                output_hint(
                    out, OUTPUT_NORMAL,
                    "Run 'dotta profile enable %s --target /path' after setup",
                    profile
                );
            }
        }

        err = initialize_state(repo, ctx->arena, fetched_profiles, out);
        if (err) {
            err = error_wrap(err, "Failed to initialize state");
            goto cleanup;
        }
    } else {
        /* No profiles fetched - initialize empty state */
        output_warning(out, OUTPUT_NORMAL, "No profiles were fetched");
        string_array_t empty = { 0 };
        err = initialize_state(repo, ctx->arena, &empty, out);
        if (err) {
            err = error_wrap(err, "Failed to initialize state");
            goto cleanup;
        }
    }

    /* Create dotta-worktree branch if it doesn't exist */
    bool worktree_exists;
    err = gitops_branch_exists(repo, "dotta-worktree", &worktree_exists);
    if (err) {
        err = error_wrap(
            err, "Failed to check for dotta-worktree branch"
        );
        goto cleanup;
    }

    if (!worktree_exists) {
        output_info(out, OUTPUT_VERBOSE, "Creating dotta-worktree branch...");

        err = gitops_create_orphan_branch(repo, "dotta-worktree");
        if (err) {
            err = error_wrap(
                err, "Failed to create dotta-worktree branch"
            );
            goto cleanup;
        }
    }

    /* Checkout dotta-worktree */
    int git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Clean working directory */
    git_checkout_options checkout_opts;
    git_checkout_options_init(&checkout_opts, GIT_CHECKOUT_OPTIONS_VERSION);
    checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    git_err = git_checkout_head(repo, &checkout_opts);
    if (git_err < 0) {
        err = error_from_git(git_err);
        goto cleanup;
    }

    /* Seed baseline .dottaignore on dotta-worktree with default patterns.
     *
     * dotta-worktree is filtered from push/fetch (see upstream.c), so a cloned
     * machine starts without one. Seeding here gives every repo the same visible,
     * editable starting point that `dotta init` creates — and ensures the safety
     * defaults are applied via the baseline path rather than only through the
     * compiled fallback.
     *
     * Seeded once: a branch that already carries the file is left alone. */
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
            output_newline(out, OUTPUT_NORMAL);

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
        output_newline(out, OUTPUT_NORMAL);
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
    output_newline(out, OUTPUT_NORMAL);
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
        output_newline(out, OUTPUT_NORMAL);
    }

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

    /* All-or-nothing: a fatal error after the clone landed must not leave a
     * half-initialized repository that blocks the retry (git_clone refuses a
     * non-empty directory). Runs after the repo handle is closed so nothing holds
     * the directory open. */
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
