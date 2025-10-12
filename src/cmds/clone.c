/**
 * clone.c - Clone dotta repository implementation
 */

#include "clone.h"

#include <git2.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "infra/path.h"
#include "utils/bootstrap.h"
#include "utils/config.h"

/**
 * Extract repository name from URL
 */
static char *extract_repo_name(const char *url) {
    const char *last_slash = strrchr(url, '/');
    if (!last_slash) {
        return strdup("dotta-repo");
    }

    const char *name = last_slash + 1;

    /* Remove .git extension if present */
    size_t len = strlen(name);
    if (len > 4 && strcmp(name + len - 4, ".git") == 0) {
        len -= 4;
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
 * Prompt user for confirmation
 */
static bool prompt_confirm(const char *message) {
    printf("%s (y/n): ", message);
    fflush(stdout);

    char response[10];
    if (!fgets(response, sizeof(response), stdin)) {
        return false;
    }

    return (response[0] == 'y' || response[0] == 'Y');
}

/**
 * Clone command implementation
 */
error_t *cmd_clone(const cmd_clone_options_t *opts) {
    CHECK_NULL(opts);
    CHECK_NULL(opts->url);

    error_t *err = NULL;
    git_repository *repo = NULL;
    char *local_path = NULL;
    bool allocated_path = false;
    dotta_config_t *config = NULL;

    /* Determine local path */
    if (opts->path) {
        local_path = (char *)opts->path;
    } else {
        /* Try to load config to get default repo location */
        err = config_load(NULL, &config);
        if (err) {
            /* If config doesn't exist, create default config */
            error_free(err);
            config = config_create_default();
        }

        if (config && config->repo_dir) {
            /* Use default repo location */
            err = path_expand_home(config->repo_dir, &local_path);
            if (err) {
                config_free(config);
                return error_wrap(err, "Failed to expand default repo path");
            }
            allocated_path = true;
        } else {
            /* Fallback: extract repo name from URL */
            local_path = extract_repo_name(opts->url);
            if (!local_path) {
                if (config) config_free(config);
                return ERROR(ERR_MEMORY, "Failed to allocate repository name");
            }
            allocated_path = true;
        }

        if (config) {
            config_free(config);
        }
    }

    if (!opts->quiet) {
        printf("Cloning %s into '%s'...\n", opts->url, local_path);
    }

    /* Clone repository */
    err = gitops_clone(&repo, opts->url, local_path);
    if (err) {
        if (allocated_path) free(local_path);
        return error_wrap(err, "Failed to clone repository");
    }

    /* Create local tracking branches for all remote tracking refs */
    size_t branch_count = 0;
    git_reference_iterator *iter = NULL;
    int git_err;

    /* Iterate over all references */
    git_err = git_reference_iterator_new(&iter, repo);
    if (git_err < 0) {
        gitops_close_repository(repo);
        if (allocated_path) free(local_path);
        return error_from_git(git_err);
    }

    git_reference *ref = NULL;
    while (git_reference_next(&ref, iter) == 0) {
        const char *refname = git_reference_name(ref);

        /* Only process remote tracking branches */
        if (strncmp(refname, "refs/remotes/origin/", 20) != 0) {
            git_reference_free(ref);
            continue;
        }

        /* Extract branch name */
        const char *branch_name = refname + 20;

        /* Skip dotta-worktree if it exists remotely */
        if (strcmp(branch_name, "dotta-worktree") == 0) {
            git_reference_free(ref);
            continue;
        }

        /* Skip HEAD */
        if (strcmp(branch_name, "HEAD") == 0) {
            git_reference_free(ref);
            continue;
        }

        /* Check if local branch already exists */
        bool exists;
        err = gitops_branch_exists(repo, branch_name, &exists);
        if (err) {
            error_free(err);
            git_reference_free(ref);
            continue;
        }

        if (!exists) {
            /* Create local tracking branch */
            const git_oid *target_oid = git_reference_target(ref);
            if (target_oid) {
                char local_refname[256];
                snprintf(local_refname, sizeof(local_refname),
                        "refs/heads/%s", branch_name);

                git_reference *local_ref = NULL;
                git_err = git_reference_create(&local_ref, repo, local_refname,
                                              target_oid, 0, NULL);
                if (git_err == 0) {
                    git_reference_free(local_ref);
                    branch_count++;
                }
            }
        } else {
            branch_count++;
        }

        git_reference_free(ref);
    }

    git_reference_iterator_free(iter);

    if (opts->verbose) {
        printf("Created %zu local tracking branch%s\n",
               branch_count, branch_count == 1 ? "" : "es");
    }

    /* Create dotta-worktree branch if it doesn't exist */
    bool worktree_exists;
    err = gitops_branch_exists(repo, "dotta-worktree", &worktree_exists);
    if (err) {
        gitops_close_repository(repo);
        if (allocated_path) free(local_path);
        return error_wrap(err, "Failed to check for dotta-worktree branch");
    }

    if (!worktree_exists) {
        if (opts->verbose) {
            printf("Creating dotta-worktree branch...\n");
        }

        err = gitops_create_orphan_branch(repo, "dotta-worktree");
        if (err) {
            gitops_close_repository(repo);
            if (allocated_path) free(local_path);
            return error_wrap(err, "Failed to create dotta-worktree branch");
        }
    }

    /* Checkout dotta-worktree */
    git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        gitops_close_repository(repo);
        if (allocated_path) free(local_path);
        return error_from_git(git_err);
    }

    /* Clean working directory */
    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    git_err = git_checkout_head(repo, &checkout_opts);
    if (git_err < 0) {
        gitops_close_repository(repo);
        if (allocated_path) free(local_path);
        return error_from_git(git_err);
    }

    /* Bootstrap detection and execution */
    bool run_bootstrap = false;
    bool bootstrap_available = false;
    profile_list_t *detected_profiles = NULL;

    if (!opts->no_bootstrap) {
        /* Auto-detect profiles for this machine */
        err = profile_detect_auto(repo, &detected_profiles);
        if (err) {
            /* Non-fatal - continue without bootstrap */
            error_free(err);
        } else if (detected_profiles && detected_profiles->count > 0) {
            /* Check if any detected profiles have bootstrap scripts */
            for (size_t i = 0; i < detected_profiles->count; i++) {
                if (bootstrap_exists(repo, detected_profiles->profiles[i].name, NULL)) {
                    bootstrap_available = true;
                    break;
                }
            }

            if (bootstrap_available && !opts->quiet) {
                printf("\nAuto-detected profiles for this machine:\n");
                for (size_t i = 0; i < detected_profiles->count; i++) {
                    printf("  - %s\n", detected_profiles->profiles[i].name);
                }

                printf("\nFound bootstrap scripts:\n");
                for (size_t i = 0; i < detected_profiles->count; i++) {
                    if (bootstrap_exists(repo, detected_profiles->profiles[i].name, NULL)) {
                        printf("  ✓ %s/.dotta/bootstrap\n", detected_profiles->profiles[i].name);
                    }
                }
                printf("\n");
            }

            /* Determine if we should run bootstrap */
            if (bootstrap_available) {
                if (opts->bootstrap) {
                    /* --bootstrap flag set, run automatically */
                    run_bootstrap = true;
                } else if (!opts->quiet) {
                    /* Prompt user */
                    run_bootstrap = prompt_confirm("Would you like to execute bootstrap scripts now?");
                }
            }
        }
    }

    /* Execute bootstrap if requested */
    if (run_bootstrap && detected_profiles) {
        printf("\n");
        err = bootstrap_run_for_profiles(repo, local_path,
                                         (struct profile_list *)detected_profiles,
                                         false, true);
        if (err) {
            profile_list_free(detected_profiles);
            gitops_close_repository(repo);
            if (allocated_path) free(local_path);
            return error_wrap(err, "Bootstrap failed");
        }
    }

    /* Cleanup */
    if (detected_profiles) {
        profile_list_free(detected_profiles);
    }

    gitops_close_repository(repo);

    /* Success message */
    if (!opts->quiet) {
        printf("\nDotta repository cloned successfully!\n");

        if (run_bootstrap) {
            printf("\nBootstrap complete!\n");
        }

        printf("\nNext steps:\n");
        if (!run_bootstrap && bootstrap_available) {
            printf("  dotta bootstrap        # Run bootstrap scripts\n");
        }
        printf("  dotta apply            # Apply profiles to your system\n");
        printf("  dotta status           # View current state\n");
        printf("\n");
    }

    if (allocated_path) free(local_path);
    return NULL;
}
