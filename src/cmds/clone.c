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
#include <string.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/path.h"
#include "sys/bootstrap.h"
#include "sys/gitops.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/bootstrap.h"

/* Default repository name when URL parsing fails */
#define DEFAULT_REPO_NAME "dotta-repo"

/**
 * Extract repository name from URL
 *
 * Handles both HTTP-style URLs (https://host/user/repo.git)
 * and SCP-style URLs (git@host:user/repo.git)
 */
static char *extract_repo_name(const char *url) {
    const char *last_slash = strrchr(url, '/');
    const char *last_colon = strrchr(url, ':');

    /* Use the rightmost separator (either / or :) */
    const char *separator = NULL;
    if (last_slash && last_colon) {
        separator = (last_slash > last_colon) ? last_slash : last_colon;
    } else if (last_slash) {
        separator = last_slash;
    } else if (last_colon) {
        separator = last_colon;
    }

    /* No separator found - use default name */
    if (!separator) {
        return strdup(DEFAULT_REPO_NAME);
    }

    const char *name = separator + 1;

    /* Handle edge case: URL ends with separator */
    if (*name == '\0') {
        return strdup(DEFAULT_REPO_NAME);
    }

    /* Remove .git extension if present */
    size_t len = strlen(name);
    if (len > 4 && strcmp(name + len - 4, ".git") == 0) {
        len -= 4;
    }

    /* Edge case: name was only ".git" */
    if (len == 0) {
        return strdup(DEFAULT_REPO_NAME);
    }

    char *repo_name = malloc(len + 1);
    if (!repo_name) {
        return NULL;
    }

    memcpy(repo_name, name, len);
    repo_name[len] = '\0';

    return repo_name;
}

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
 * @param fetched_profiles Optional: array to populate with successfully fetched names (can be NULL)
 * @return Error or NULL on success
 */
static error_t *fetch_profiles(
    git_repository *repo,
    const char *remote_name,
    char **profiles,
    size_t count,
    output_ctx_t *out,
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
    output_ctx_t *out,
    transfer_context_t *xfer,
    string_array_t **fetched_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    CHECK_NULL(fetched_profiles);

    output_section(out, OUTPUT_NORMAL, "Fetching all remote profiles");

    /* List all remote tracking branches */
    string_array_t *all_branches = NULL;
    error_t *err = gitops_list_remote_branches(
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
    const string_array_t *profiles,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    /* Create state database (with or without profiles) */
    state_t *state = NULL;
    error_t *err = state_open(repo, &state);
    if (err) {
        return error_wrap(err, "Failed to initialize state database");
    }

    /* Set enabled profiles and populate manifest */
    if (profiles->count > 0) {
        err = state_set_profiles(state, profiles);
        if (err) {
            state_free(state);
            return error_wrap(err, "Failed to set profiles in state");
        }

        /* Populate manifest from enabled profiles
         *
         * This populates the virtual_manifest table by walking through all
         * enabled profiles and adding their files with correct precedence.
         * Without this, the manifest would be empty and 'dotta apply' would
         * have nothing to deploy. */
        err = manifest_rebuild(repo, state, profiles);
        if (err) {
            state_free(state);
            return error_wrap(err, "Failed to populate manifest");
        }
    }

    /* Commit transaction */
    err = state_save(repo, state);
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
 * Clone command implementation
 */
error_t *cmd_clone(const dotta_ctx_t *ctx, const cmd_clone_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->url);

    const config_t *config = ctx->config;
    output_ctx_t *out = ctx->out;

    error_t *err = NULL;
    error_t *final_err = NULL;
    git_repository *repo = NULL;
    const char *local_path = NULL;
    bool allocated_path = false;
    transfer_context_t *xfer = NULL;
    string_array_t *fetched_profiles = NULL;
    string_array_t *detected_profiles = NULL;
    string_array_t bootstrap_found STRING_ARRAY_AUTO = { 0 };

    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    } else if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Determine local path */
    if (opts->path) {
        local_path = opts->path;
    } else {
        if (config->repo_dir) {
            /* Use default repo location from config */
            char *expanded_path = NULL;
            err = path_expand_home(config->repo_dir, &expanded_path);
            if (err) {
                final_err = error_wrap(
                    err, "Failed to expand default repo path"
                );
                goto cleanup;
            }
            local_path = expanded_path;
            allocated_path = true;
        } else {
            /* Fallback: extract repo name from URL */
            local_path = extract_repo_name(opts->url);
            if (!local_path) {
                final_err = ERROR(
                    ERR_MEMORY, "Failed to allocate repository name"
                );
                goto cleanup;
            }
            allocated_path = true;
        }
    }

    output_section(out, OUTPUT_NORMAL, "Cloning dotta repository");
    output_info(out, OUTPUT_NORMAL, "  URL: %s", opts->url);
    output_info(out, OUTPUT_NORMAL, "  Path: %s", local_path);

    /* Create transfer context for progress reporting and credentials */
    xfer = transfer_context_create(out, opts->url);
    if (!xfer) {
        final_err = ERROR(ERR_MEMORY, "Failed to create transfer context");
        goto cleanup;
    }

    /* Clone repository with progress reporting */
    err = gitops_clone(&repo, opts->url, local_path, xfer);
    if (err) {
        final_err = error_wrap(err, "Failed to clone repository");
        goto cleanup;
    }

    /* Determine which profiles to fetch */
    fetched_profiles = string_array_new(0);
    if (!fetched_profiles) {
        final_err = ERROR(ERR_MEMORY, "Failed to create profile array");
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
        err = gitops_list_remote_branches(repo, "origin", &remote_branches);
        if (err) {
            output_warning(
                out, OUTPUT_NORMAL, "Failed to list remote branches: %s",
                error_message(err)
            );
            error_free(err);
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
     * Profiles with custom/ files require a machine-specific --prefix to resolve
     * deployment paths. Without it, enabling them creates half-configured state
     * that breaks other operations. Filter them out and hint the user instead.
     * The branch data is already fetched and available locally. */
    if (fetched_profiles->count > 0) {
        string_array_t *profiles = string_array_new(0);
        if (!profiles) {
            final_err = ERROR(ERR_MEMORY, "Failed to allocate profile array");
            goto cleanup;
        }

        for (size_t i = 0; i < fetched_profiles->count; i++) {
            const char *profile = fetched_profiles->items[i];
            bool has_custom = false;

            error_t *check_err = profile_has_custom_files(repo, profile, &has_custom);
            if (check_err) {
                error_free(check_err);
                /* Can't determine — include it to avoid silently dropping profiles */
                string_array_push(profiles, profile);
                continue;
            }

            if (has_custom) {
                output_warning(
                    out, OUTPUT_NORMAL, "Profile '%s' requires --prefix (not enabled)",
                    profile
                );
                output_hint(
                    out, OUTPUT_NORMAL, "Run: dotta profile enable --prefix <path> %s",
                    profile
                );
            } else {
                string_array_push(profiles, profile);
            }
        }

        err = initialize_state(repo, profiles, out);
        if (err) {
            output_error(out, "Failed to initialize state: %s", error_message(err));
            error_free(err);
        }

        string_array_free(profiles);
    } else {
        /* No profiles fetched - initialize empty state */
        output_warning(out, OUTPUT_NORMAL, "No profiles were fetched");
        string_array_t empty = { 0 };
        err = initialize_state(repo, &empty, out);
        if (err) {
            output_error(out, "Failed to initialize state: %s", error_message(err));
            error_free(err);
        }
    }

    /* Create dotta-worktree branch if it doesn't exist */
    bool worktree_exists;
    err = gitops_branch_exists(repo, "dotta-worktree", &worktree_exists);
    if (err) {
        final_err = error_wrap(
            err, "Failed to check for dotta-worktree branch"
        );
        goto cleanup;
    }

    if (!worktree_exists) {
        output_info(out, OUTPUT_VERBOSE, "Creating dotta-worktree branch...");

        err = gitops_create_orphan_branch(repo, "dotta-worktree");
        if (err) {
            final_err = error_wrap(
                err, "Failed to create dotta-worktree branch"
            );
            goto cleanup;
        }
    }

    /* Checkout dotta-worktree */
    int git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        final_err = error_from_git(git_err);
        goto cleanup;
    }

    /* Clean working directory */
    git_checkout_options checkout_opts;
    git_checkout_options_init(&checkout_opts, GIT_CHECKOUT_OPTIONS_VERSION);
    checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    git_err = git_checkout_head(repo, &checkout_opts);
    if (git_err < 0) {
        final_err = error_from_git(git_err);
        goto cleanup;
    }

    /* Bootstrap detection and execution.
     *
     * Single-pass filter: walk fetched_profiles once, collect those
     * with a .bootstrap script into `bootstrap_found`, then display,
     * prompt, and (conditionally) fire. bootstrap_available is a
     * simple derived flag used by the final "Next steps" hint. */
    bool run_bootstrap = false;
    bool bootstrap_available = false;

    /* Check bootstrap scripts in all fetched profiles */
    if (opts->bootstrap_mode != CLONE_BOOTSTRAP_SKIP &&
        fetched_profiles->count > 0) {
        /* Check if any fetched profiles have bootstrap scripts */
        for (size_t i = 0; i < fetched_profiles->count; i++) {
            const char *profile = fetched_profiles->items[i];
            if (!bootstrap_exists(repo, profile)) continue;
            err = string_array_push(&bootstrap_found, profile);
            if (err) {
                final_err = error_wrap(
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
            /* Non-fatal — the clone itself succeeded. */
        }
    }

    /* Success - print messages before cleanup */
    output_newline(out, OUTPUT_NORMAL);
    output_success(out, OUTPUT_NORMAL, "Dotta repository cloned successfully!");

    if (run_bootstrap) output_success(out, OUTPUT_NORMAL, "Bootstrap complete!");

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
    if (allocated_path && local_path) {
        /* Safe to cast: we know it's heap-allocated when allocated_path is true */
        free((char *) local_path);
    }

    return final_err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Interpret the 1-2 raw positionals: first is the URL, optional second
 * is the local path. Ordering matters (URL must precede path), so the
 * engine's classifier (position-agnostic by design) isn't expressive
 * enough; a raw bucket plus this post_parse hook keeps the logic local
 * and linear.
 */
static error_t *clone_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_clone_options_t *o = opts_v;

    /* POSITIONAL_RAW enforces min=1, max=2 — count is 1 or 2 here. */
    o->url = o->positional_args[0];
    if (o->positional_count >= 2) {
        o->path = o->positional_args[1];
    }
    return NULL;
}

/**
 * Mutual-exclusion check: `--all` and `-p/--profile(s)` cannot both
 * constrain the fetch set. Everything else has already been validated
 * by the engine's per-row rules.
 */
static error_t *clone_validate(
    void *opts_v, const args_command_t *cmd
) {
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

static error_t *clone_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_clone(ctx, (const cmd_clone_options_t *) opts_v);
}

static const args_opt_t clone_opts[] = {
    ARGS_GROUP("Options:"),
    /* Three aliases — `-p`, `--profile`, `--profiles` — preserving
     * the flag names the legacy parser accepted. Arity differs:
     * ARGS_APPEND binds one value per occurrence, whereas the legacy
     * parser consumed every bare token until the next flag. Users
     * must write `-p a -p b` (not `-p a b`). Peer-list order is the
     * help display order: "-p, --profile, --profiles". */
    ARGS_APPEND(
        "p profile profiles", "<name>",
        cmd_clone_options_t,  profiles,        profile_count,
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
        cmd_clone_options_t,  bootstrap_mode,  CLONE_BOOTSTRAP_SKIP,
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
    /* <url> [<path>] — order-dependent. Classifier has no position
     * awareness, so a raw bucket with post_parse assignment is cleaner
     * than two POSITIONAL_ONE rows differentiated by ad-hoc classes. */
    ARGS_POSITIONAL_RAW(
        cmd_clone_options_t,  positional_args, positional_count,
        1,                    2
    ),
    ARGS_END,
};

const args_command_t spec_clone = {
    .name        = "clone",
    .summary     = "Clone an existing dotta repository",
    .usage       = "%s clone [options] <url> [path]",
    .description =
        "Fetch a dotta repository and auto-detect the profiles that\n"
        "apply to this system. Fetched profiles are enabled immediately\n"
        "and recorded in state.\n",
    .notes       =
        "Profile Selection:\n"
        "  (default)       Auto-detect profiles for this system\n"
        "                  (global, <os>, hosts/<hostname> and variants).\n"
        "  --all           Hub mode: fetch every remote profile.\n"
        "  -p <name>       Fetch specific profiles explicitly (repeatable).\n"
        "\n"
        "Profile Behavior:\n"
        "  Fetched profiles are enabled automatically. Run '%s profile\n"
        "  list' to inspect enabled vs available profiles, and '%s\n"
        "  profile enable <name>' to add one later.\n"
        "\n"
        "Bootstrap Integration:\n"
        "  After cloning, dotta checks fetched profiles for a .bootstrap\n"
        "  script. The default prompts before executing. --bootstrap runs\n"
        "  them without confirmation; --no-bootstrap skips the check.\n",
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
    .validate    = clone_validate,
    .payload     = &dotta_ext_none,
    .dispatch    = clone_dispatch,
};
