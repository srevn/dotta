/**
 * clone.c - Clone dotta repository implementation
 *
 * Smart profile management
 * - Auto-detects relevant profiles by default
 * - Fetches only detected/specified profiles
 * - Initializes state with fetched profiles
 * - Supports hub mode (--all) for backup workflows
 */

#include "clone.h"

#include <git2.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/credentials.h"
#include "base/error.h"
#include "base/gitops.h"
#include "core/bootstrap.h"
#include "core/profiles.h"
#include "core/state.h"
#include "core/upstream.h"
#include "infra/path.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"

/* Default repository name when URL parsing fails */
#define DEFAULT_REPO_NAME "dotta-repo"

/* Maximum length for remote reference prefix (refs/remotes/<name>/) */
#define REMOTE_REF_PREFIX_MAX 256

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
 * @param profile_names Array of profile names to fetch
 * @param count Number of profiles
 * @param out Output context for messages
 * @param cred_ctx Credential context
 * @param fetched_count Output: number successfully fetched (can be NULL)
 * @param fetched_names Optional: array to populate with successfully fetched names (can be NULL)
 * @return Error or NULL on success
 */
static error_t *fetch_profiles(
    git_repository *repo,
    const char *remote_name,
    const char **profile_names,
    size_t count,
    output_ctx_t *out,
    credential_context_t *cred_ctx,
    size_t *fetched_count,
    string_array_t *fetched_names
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);
    CHECK_NULL(out);

    size_t local_count = 0;
    error_t *err = NULL;

    for (size_t i = 0; i < count; i++) {
        const char *profile_name = profile_names[i];

        if (output_colors_enabled(out)) {
            output_info(out, "  Fetching %s...", profile_name);
        }

        /* Fetch the profile branch */
        err = gitops_fetch_branch(repo, remote_name, profile_name, cred_ctx);
        if (err) {
            output_warning(out, "Failed to fetch '%s': %s",
                          profile_name, error_message(err));
            error_free(err);
            continue;
        }

        /* Create local tracking branch if it doesn't already exist */
        bool already_exists = profile_exists(repo, profile_name);
        if (already_exists) {
            /* Branch already exists (e.g., from git_clone) - skip creation */
            local_count++;
        } else {
            /* Create new local tracking branch */
            err = upstream_create_tracking_branch(repo, remote_name, profile_name);
            if (err) {
                output_warning(out, "Failed to create local branch '%s': %s",
                              profile_name, error_message(err));
                error_free(err);
                continue;
            }
            local_count++;
        }

        /* Add to fetched names array if provided */
        if (fetched_names) {
            string_array_push(fetched_names, profile_name);
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
 * @param cred_ctx Credential context
 * @param fetched_profiles Output: fetched profile names array
 * @return Error or NULL on success
 */
static error_t *fetch_all_profiles(
    git_repository *repo,
    const char *remote_name,
    output_ctx_t *out,
    credential_context_t *cred_ctx,
    string_array_t **fetched_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    CHECK_NULL(fetched_profiles);

    output_section(out, "Fetching all remote profiles");

    /* Discover all remote branches */
    string_array_t *all_branches = string_array_create();
    if (!all_branches) {
        return ERROR(ERR_MEMORY, "Failed to create array");
    }

    /* Build remote reference prefix */
    char prefix[REMOTE_REF_PREFIX_MAX];
    int ret = snprintf(prefix, sizeof(prefix), "refs/remotes/%s/", remote_name);
    if (ret < 0 || (size_t)ret >= sizeof(prefix)) {
        string_array_free(all_branches);
        return ERROR(ERR_INVALID_ARG, "Remote name too long");
    }
    size_t prefix_len = strlen(prefix);

    /* Iterate remote refs to find all branches */
    git_reference_iterator *iter = NULL;
    int git_err = git_reference_iterator_new(&iter, repo);
    if (git_err < 0) {
        string_array_free(all_branches);
        return error_from_git(git_err);
    }

    git_reference *ref = NULL;
    while (git_reference_next(&ref, iter) == 0) {
        const char *refname = git_reference_name(ref);

        /* Only process remote tracking branches for our remote */
        if (strncmp(refname, prefix, prefix_len) == 0) {
            const char *branch_name = refname + prefix_len;

            /* Skip dotta-worktree and HEAD */
            if (strcmp(branch_name, "dotta-worktree") != 0 &&
                strcmp(branch_name, "HEAD") != 0) {
                string_array_push(all_branches, branch_name);
            }
        }

        git_reference_free(ref);
    }

    git_reference_iterator_free(iter);

    /* Create array for successfully fetched profiles */
    string_array_t *successful = string_array_create();
    if (!successful) {
        string_array_free(all_branches);
        return ERROR(ERR_MEMORY, "Failed to create fetched profiles array");
    }

    /* Fetch and create local branches */
    size_t fetched_count = 0;
    error_t *err = fetch_profiles(repo, remote_name,
                                  (const char **)all_branches->items,
                                  all_branches->count,
                                  out, cred_ctx, &fetched_count, successful);

    string_array_free(all_branches);

    if (err) {
        string_array_free(successful);
        return err;
    }

    output_success(out, "Fetched %zu profile%s\n",
                  fetched_count, fetched_count == 1 ? "" : "s");

    *fetched_profiles = successful;
    return NULL;
}

/**
 * Handle no-profiles-detected case
 *
 * Provides user guidance when auto-detection finds no profiles.
 * Offers to fetch 'global' as a sensible fallback.
 *
 * @param repo Repository
 * @param remote_name Remote name
 * @param out Output context
 * @param cred_ctx Credential context
 * @param fallback_profiles Output: fallback profiles to use
 * @return Error or NULL on success
 */
static error_t *handle_no_profiles_detected(
    git_repository *repo,
    const char *remote_name,
    output_ctx_t *out,
    credential_context_t *cred_ctx,
    string_array_t **fallback_profiles
) {
    CHECK_NULL(repo);
    CHECK_NULL(out);
    CHECK_NULL(fallback_profiles);

    output_warning(out, "No profiles auto-detected for this system\n");

    /* List available remote profiles */
    string_array_t *remote_branches = NULL;
    error_t *err = upstream_discover_branches(repo, remote_name, &remote_branches);

    if (!err && remote_branches && string_array_size(remote_branches) > 0) {
        output_section(out, "Available remote profiles");
        for (size_t i = 0; i < string_array_size(remote_branches); i++) {
            output_printf(out, OUTPUT_NORMAL, "  • %s\n", string_array_get(remote_branches, i));
        }
        output_newline(out);

        /* Check if 'global' exists */
        bool has_global = false;
        for (size_t i = 0; i < string_array_size(remote_branches); i++) {
            if (strcmp(string_array_get(remote_branches, i), "global") == 0) {
                has_global = true;
                break;
            }
        }

        if (has_global) {
            output_info(out, "Fetching 'global' profile as fallback...\n");

            /* Fetch global */
            const char *global_name = "global";
            *fallback_profiles = string_array_create();
            if (!*fallback_profiles) {
                string_array_free(remote_branches);
                return ERROR(ERR_MEMORY, "Failed to create fallback array");
            }

            err = fetch_profiles(repo, remote_name, &global_name, 1,
                                out, cred_ctx, NULL, *fallback_profiles);

            if (!err && string_array_size(*fallback_profiles) > 0) {
                output_success(out, "Using 'global' profile\n");
            } else {
                /* Failed to fetch - clean up */
                string_array_free(*fallback_profiles);
                *fallback_profiles = NULL;
            }
        } else {
            output_info(out, "No 'global' profile found.");
            output_info(out, "Run 'dotta profile activate <name>' after setup\n");
        }
    }

    string_array_free(remote_branches);
    return NULL;
}

/**
 * Initialize state with fetched profiles
 *
 * @param repo Repository
 * @param profile_names Profile names to set as active
 * @param count Number of profiles
 * @param out Output context
 * @return Error or NULL on success
 */
static error_t *initialize_state(
    git_repository *repo,
    const char **profile_names,
    size_t count,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);
    CHECK_NULL(out);

    if (count == 0) {
        /* No profiles - create empty state */
        state_t *state = NULL;
        error_t *err = state_create_empty(&state);
        if (err) {
            return error_wrap(err, "Failed to create empty state");
        }

        err = state_save(repo, state);
        state_free(state);
        return err;
    }

    /* Create state with active profiles */
    state_t *state = NULL;
    error_t *err = state_create_empty(&state);
    if (err) {
        return error_wrap(err, "Failed to create state");
    }

    err = state_set_profiles(state, profile_names, count);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to set profiles in state");
    }

    err = state_save(repo, state);
    if (err) {
        state_free(state);
        return error_wrap(err, "Failed to save state");
    }

    state_free(state);

    if (output_colors_enabled(out)) {
        output_success(out, "Initialized active profiles: ");
        for (size_t i = 0; i < count; i++) {
            output_printf(out, OUTPUT_NORMAL, "%s%s",
                   profile_names[i],
                   (i < count - 1) ? ", " : "\n");
        }
    }

    return NULL;
}

/**
 * Clone command implementation
 */
error_t *cmd_clone(const cmd_clone_options_t *opts) {
    CHECK_NULL(opts);
    CHECK_NULL(opts->url);

    error_t *err = NULL;
    error_t *final_err = NULL;
    git_repository *repo = NULL;
    const char *local_path = NULL;
    bool allocated_path = false;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;
    credential_context_t *cred_ctx = NULL;
    string_array_t *fetched_profiles = NULL;
    profile_list_t *detected_profiles = NULL;

    /* Create output context */
    out = output_create();
    if (!out) {
        return ERROR(ERR_MEMORY, "Failed to create output context");
    }

    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    } else if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Determine local path */
    if (opts->path) {
        local_path = opts->path;
    } else {
        /* Try to load config to get default repo location */
        err = config_load(NULL, &config);
        if (err) {
            /* If config doesn't exist, create default config */
            error_free(err);
            err = NULL;
            config = config_create_default();
        }

        if (config && config->repo_dir) {
            /* Use default repo location */
            char *expanded_path = NULL;
            err = path_expand_home(config->repo_dir, &expanded_path);
            if (err) {
                final_err = error_wrap(err, "Failed to expand default repo path");
                goto cleanup;
            }
            local_path = expanded_path;
            allocated_path = true;
        } else {
            /* Fallback: extract repo name from URL */
            local_path = extract_repo_name(opts->url);
            if (!local_path) {
                final_err = ERROR(ERR_MEMORY, "Failed to allocate repository name");
                goto cleanup;
            }
            allocated_path = true;
        }

        if (config) {
            config_free(config);
            config = NULL;
        }
    }

    output_section(out, "Cloning dotta repository");
    output_info(out, "  URL: %s", opts->url);
    output_info(out, "  Path: %s\n", local_path);

    /* Clone repository */
    err = gitops_clone(&repo, opts->url, local_path);
    if (err) {
        final_err = error_wrap(err, "Failed to clone repository");
        goto cleanup;
    }

    /* Setup credential context */
    git_remote *remote_obj = NULL;
    char *remote_url = NULL;
    if (git_remote_lookup(&remote_obj, repo, "origin") == 0) {
        const char *url = git_remote_url(remote_obj);
        if (url) {
            remote_url = strdup(url);
        }
        git_remote_free(remote_obj);
    }

    cred_ctx = credential_context_create(remote_url);
    free(remote_url);

    /* Determine which profiles to fetch */
    fetched_profiles = string_array_create();
    if (!fetched_profiles) {
        final_err = ERROR(ERR_MEMORY, "Failed to create profile array");
        goto cleanup;
    }

    if (opts->profiles && opts->profile_count > 0) {
        /* Explicit profile selection */
        output_section(out, "Fetching specified profiles");

        size_t fetched_count = 0;
        err = fetch_profiles(repo, "origin", opts->profiles, opts->profile_count,
                            out, cred_ctx, &fetched_count, fetched_profiles);

        if (err) {
            output_error(out, "Failed to fetch profiles: %s", error_message(err));
            /* Continue - some profiles may have been fetched */
            error_free(err);
        }

        output_success(out, "Fetched %zu of %zu specified profile%s\n",
                      fetched_count, opts->profile_count,
                      opts->profile_count == 1 ? "" : "s");

    } else if (opts->fetch_all) {
        /* Hub mode - fetch all profiles */
        string_array_t *all_profiles = NULL;
        err = fetch_all_profiles(repo, "origin", out, cred_ctx, &all_profiles);

        if (err) {
            output_error(out, "Failed to fetch all profiles: %s", error_message(err));
            error_free(err);
        } else {
            /* Use all fetched profiles */
            string_array_free(fetched_profiles);
            fetched_profiles = all_profiles;
        }

    } else {
        /* Default: auto-detect profiles for this machine */
        output_section(out, "Auto-detecting profiles for this system");

        err = profile_detect_auto(repo, &detected_profiles);
        if (err) {
            output_warning(out, "Failed to auto-detect profiles: %s", error_message(err));
            error_free(err);
            detected_profiles = NULL;
        }

        if (detected_profiles && detected_profiles->count > 0) {
            /* Show detected profiles */
            for (size_t i = 0; i < detected_profiles->count; i++) {
                output_info(out, "  • %s", detected_profiles->profiles[i].name);
            }
            output_newline(out);

            /* Build profile names array */
            const char **profile_names = malloc(detected_profiles->count * sizeof(char *));
            if (!profile_names) {
                final_err = ERROR(ERR_MEMORY, "Failed to allocate profile names");
                goto cleanup;
            }

            for (size_t i = 0; i < detected_profiles->count; i++) {
                profile_names[i] = detected_profiles->profiles[i].name;
            }

            /* Fetch detected profiles */
            size_t fetched_count = 0;
            err = fetch_profiles(repo, "origin", profile_names, detected_profiles->count,
                                out, cred_ctx, &fetched_count, fetched_profiles);

            free(profile_names);

            if (err) {
                output_warning(out, "Some profiles failed to fetch: %s", error_message(err));
                error_free(err);
            }

            if (fetched_count > 0) {
                output_success(out, "Fetched %zu profile%s\n",
                              fetched_count, fetched_count == 1 ? "" : "s");
            }

        } else {
            /* No profiles detected - handle gracefully */
            string_array_t *fallback = NULL;
            err = handle_no_profiles_detected(repo, "origin", out, cred_ctx, &fallback);
            if (!err && fallback) {
                /* Use fallback profiles */
                string_array_free(fetched_profiles);
                fetched_profiles = fallback;
            } else if (err) {
                error_free(err);
            }
        }
    }

    /* Initialize state with fetched profiles */
    if (string_array_size(fetched_profiles) > 0) {
        const char **profile_names = (const char **)fetched_profiles->items;
        size_t profile_count = string_array_size(fetched_profiles);

        err = initialize_state(repo, profile_names, profile_count, out);
        if (err) {
            output_error(out, "Failed to initialize state: %s", error_message(err));
            error_free(err);
        }
    } else {
        /* No profiles fetched - initialize empty state */
        output_warning(out, "No profiles were fetched");
        err = initialize_state(repo, NULL, 0, out);
        if (err) {
            output_error(out, "Failed to initialize state: %s", error_message(err));
            error_free(err);
        }
    }

    /* Create dotta-worktree branch if it doesn't exist */
    bool worktree_exists;
    err = gitops_branch_exists(repo, "dotta-worktree", &worktree_exists);
    if (err) {
        final_err = error_wrap(err, "Failed to check for dotta-worktree branch");
        goto cleanup;
    }

    if (!worktree_exists) {
        if (opts->verbose) {
            output_info(out, "Creating dotta-worktree branch...");
        }

        err = gitops_create_orphan_branch(repo, "dotta-worktree");
        if (err) {
            final_err = error_wrap(err, "Failed to create dotta-worktree branch");
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
    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    git_err = git_checkout_head(repo, &checkout_opts);
    if (git_err < 0) {
        final_err = error_from_git(git_err);
        goto cleanup;
    }

    /* Bootstrap detection and execution */
    bool run_bootstrap = false;
    bool bootstrap_available = false;

    /* Check bootstrap scripts in all fetched profiles */
    if (!opts->no_bootstrap && string_array_size(fetched_profiles) > 0) {
        /* Check if any fetched profiles have bootstrap scripts */
        for (size_t i = 0; i < string_array_size(fetched_profiles); i++) {
            const char *profile_name = string_array_get(fetched_profiles, i);
            if (bootstrap_exists(repo, profile_name, NULL)) {
                bootstrap_available = true;
                break;
            }
        }

        if (bootstrap_available) {
            output_newline(out);
            output_section(out, "Bootstrap scripts available");

            for (size_t i = 0; i < string_array_size(fetched_profiles); i++) {
                const char *profile_name = string_array_get(fetched_profiles, i);
                if (bootstrap_exists(repo, profile_name, NULL)) {
                    output_info(out, "  ✓ %s/.dotta/bootstrap", profile_name);
                }
            }
            output_newline(out);

            /* Determine if we should run bootstrap */
            if (opts->bootstrap) {
                /* --bootstrap flag set, run automatically */
                run_bootstrap = true;
            } else if (!opts->quiet) {
                /* Prompt user */
                run_bootstrap = output_confirm(out,
                        "Would you like to execute bootstrap scripts now?", false);
            }
        }
    }

    /* Execute bootstrap if requested */
    if (run_bootstrap && string_array_size(fetched_profiles) > 0) {
        /* Load profiles for bootstrap execution */
        profile_list_t *bootstrap_profiles = NULL;
        err = profile_list_load(repo,
                               (const char **)fetched_profiles->items,
                               string_array_size(fetched_profiles),
                               false, /* non-strict: skip non-existent */
                               &bootstrap_profiles);

        if (!err && bootstrap_profiles) {
            output_newline(out);
            err = bootstrap_run_for_profiles(repo, local_path,
                                             (struct profile_list *)bootstrap_profiles,
                                             false, true);
            if (err) {
                output_error(out, "Bootstrap failed: %s", error_message(err));
                error_free(err);
                /* Non-fatal - continue */
            }
            profile_list_free(bootstrap_profiles);
        } else if (err) {
            output_warning(out, "Failed to load profiles for bootstrap: %s",
                          error_message(err));
            error_free(err);
        }
    }

    /* Success - print messages before cleanup */
    output_newline(out);
    output_success(out, "Dotta repository cloned successfully!\n");

    if (run_bootstrap) {
        output_success(out, "Bootstrap complete!\n");
    }

    output_newline(out);
    output_section(out, "Next steps");
    if (!run_bootstrap && bootstrap_available) {
        output_info(out, "  dotta bootstrap        # Run bootstrap scripts");
    }
    output_info(out, "  dotta profile list     # View active profiles");
    output_info(out, "  dotta apply            # Apply profiles to your system");
    output_info(out, "  dotta status           # View current state");
    output_newline(out);

cleanup:
    /* Cleanup resources */
    if (detected_profiles) {
        profile_list_free(detected_profiles);
    }
    if (cred_ctx) {
        credential_context_free(cred_ctx);
    }
    if (fetched_profiles) {
        string_array_free(fetched_profiles);
    }
    if (repo) {
        gitops_close_repository(repo);
    }
    if (out) {
        output_free(out);
    }
    if (allocated_path && local_path) {
        /* Safe to cast: we know it's heap-allocated when allocated_path is true */
        free((char *)local_path);
    }

    return final_err;
}
