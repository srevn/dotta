/**
 * bootstrap.c - Bootstrap command implementation
 */

#include "bootstrap.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "base/gitops.h"
#include "core/bootstrap.h"
#include "core/profiles.h"
#include "utils/config.h"
#include "utils/editor.h"
#include "utils/output.h"
#include "utils/repo.h"
#include "utils/string.h"

/* Bootstrap script template */
static const char *BOOTSTRAP_TEMPLATE =
    "#!/usr/bin/env bash\n"
    "#\n"
    "# Bootstrap script for %s profile\n"
    "#\n"
    "# This script runs after cloning the repository and before applying profiles.\n"
    "# Use it to install dependencies, set up package managers, or configure the system.\n"
    "#\n"
    "# Environment variables:\n"
    "#   DOTTA_REPO_DIR    - Path to dotta repository\n"
    "#   DOTTA_PROFILE     - Current profile name\n"
    "#   DOTTA_PROFILES    - All profiles being bootstrapped\n"
    "#   HOME              - User home directory\n"
    "#\n"
    "# Exit with non-zero status to abort the bootstrap process.\n"
    "\n"
    "set -euo pipefail\n"
    "\n"
    "echo \"Running %s bootstrap...\"\n"
    "\n"
    "# Add your bootstrap commands here.\n"
    "# Examples:\n"
    "#\n"
    "# Install package manager:\n"
    "#   if ! command -v brew >/dev/null 2>&1; then\n"
    "#       echo \"Installing Homebrew...\"\n"
    "#       /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"\n"
    "#   fi\n"
    "#\n"
    "# Install packages:\n"
    "#   brew install git curl wget\n"
    "#\n"
    "# Set system preferences (macOS):\n"
    "#   defaults write NSGlobalDomain ApplePressAndHoldEnabled -bool false\n"
    "\n"
    "echo \"%s bootstrap complete!\"\n";

/**
 * Create bootstrap script from template
 */
static error_t *bootstrap_create_template(
    git_repository *repo,
    const char *repo_dir,
    const char *profile_name,
    const char *script_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(repo_dir);
    CHECK_NULL(profile_name);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Check if profile exists */
    bool exists = false;
    error_t *err = gitops_branch_exists(repo, profile_name, &exists);
    if (err) {
        return error_wrap(err, "Failed to check if profile exists");
    }

    if (!exists) {
        return ERROR(ERR_NOT_FOUND, "Profile '%s' does not exist", profile_name);
    }

    /* Get script path */
    char *script_path = NULL;
    err = bootstrap_get_path(repo_dir, profile_name, script_name, &script_path);
    if (err) {
        return error_wrap(err, "Failed to get bootstrap script path");
    }

    /* Check if script already exists */
    if (fs_file_exists(script_path)) {
        free(script_path);
        return ERROR(ERR_EXISTS, "Bootstrap script already exists for profile '%s'", profile_name);
    }

    /* Create .dotta directory if it doesn't exist */
    char *profile_path = NULL;
    err = fs_path_join(repo_dir, profile_name, &profile_path);
    if (err) {
        free(script_path);
        return error_wrap(err, "Failed to build profile path");
    }

    char *dotta_path = NULL;
    err = fs_path_join(profile_path, ".dotta", &dotta_path);
    free(profile_path);
    if (err) {
        free(script_path);
        return error_wrap(err, "Failed to build .dotta path");
    }

    /* Create .dotta directory */
    if (!fs_is_directory(dotta_path)) {
        err = fs_create_dir(dotta_path, true);
        if (err) {
            free(dotta_path);
            free(script_path);
            return error_wrap(err, "Failed to create .dotta directory");
        }
    }
    free(dotta_path);

    /* Generate template content */
    char *content = str_format(BOOTSTRAP_TEMPLATE,
                              profile_name,
                              profile_name,
                              profile_name);
    if (!content) {
        free(script_path);
        return ERROR(ERR_MEMORY, "Failed to generate bootstrap template");
    }

    /* Create blob from in-memory content first (before writing to file) */
    git_oid blob_oid;
    size_t content_len = strlen(content);
    int git_err = git_blob_create_from_buffer(&blob_oid, repo, content, content_len);
    if (git_err < 0) {
        free(content);
        free(script_path);
        return error_from_git(git_err);
    }

    /* Now write the same content to file */
    FILE *fp = fopen(script_path, "w");
    if (!fp) {
        free(content);
        free(script_path);
        return ERROR(ERR_FS, "Failed to create bootstrap script: %s", script_path);
    }

    fprintf(fp, "%s", content);
    fclose(fp);
    free(content);

    /* Make script executable */
    if (chmod(script_path, 0755) != 0) {
        free(script_path);
        return ERROR(ERR_FS, "Failed to make bootstrap script executable");
    }

    free(script_path);  /* Done with script_path */

    /* Load current tree from profile branch */
    char *ref_name = str_format("refs/heads/%s", profile_name);
    if (!ref_name) {
        return ERROR(ERR_MEMORY, "Failed to allocate ref name");
    }

    git_tree *current_tree = NULL;
    err = gitops_load_tree(repo, ref_name, &current_tree);
    if (err) {
        free(ref_name);
        return error_wrap(err, "Failed to load tree from profile '%s'", profile_name);
    }

    /* Check if .dotta directory exists in the tree */
    const git_tree_entry *dotta_entry = git_tree_entry_byname(current_tree, ".dotta");
    git_tree *dotta_tree = NULL;
    git_treebuilder *dotta_builder = NULL;

    if (dotta_entry && git_tree_entry_type(dotta_entry) == GIT_OBJECT_TREE) {
        /* Load existing .dotta subtree */
        const git_oid *dotta_oid = git_tree_entry_id(dotta_entry);
        git_err = git_tree_lookup(&dotta_tree, repo, dotta_oid);
        if (git_err < 0) {
            git_tree_free(current_tree);
            free(ref_name);
            return error_from_git(git_err);
        }

        /* Create builder from existing .dotta tree */
        git_err = git_treebuilder_new(&dotta_builder, repo, dotta_tree);
        git_tree_free(dotta_tree);
    } else {
        /* Create new .dotta directory */
        git_err = git_treebuilder_new(&dotta_builder, repo, NULL);
    }

    if (git_err < 0) {
        git_tree_free(current_tree);
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Insert bootstrap script into .dotta tree */
    git_err = git_treebuilder_insert(NULL, dotta_builder, script_name, &blob_oid, GIT_FILEMODE_BLOB_EXECUTABLE);
    if (git_err < 0) {
        git_treebuilder_free(dotta_builder);
        git_tree_free(current_tree);
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Write the .dotta tree */
    git_oid dotta_tree_oid;
    git_err = git_treebuilder_write(&dotta_tree_oid, dotta_builder);
    git_treebuilder_free(dotta_builder);
    if (git_err < 0) {
        git_tree_free(current_tree);
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Create root tree builder */
    git_treebuilder *root_builder = NULL;
    git_err = git_treebuilder_new(&root_builder, repo, current_tree);
    git_tree_free(current_tree);
    if (git_err < 0) {
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Insert/update .dotta directory in root tree */
    git_err = git_treebuilder_insert(NULL, root_builder, ".dotta", &dotta_tree_oid, GIT_FILEMODE_TREE);
    if (git_err < 0) {
        git_treebuilder_free(root_builder);
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Write the root tree */
    git_oid tree_oid;
    git_err = git_treebuilder_write(&tree_oid, root_builder);
    git_treebuilder_free(root_builder);
    if (git_err < 0) {
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Load the new tree */
    git_tree *new_tree = NULL;
    git_err = git_tree_lookup(&new_tree, repo, &tree_oid);
    if (git_err < 0) {
        free(ref_name);
        return error_from_git(git_err);
    }

    /* Create commit */
    char *commit_message = str_format("Add bootstrap script for %s profile", profile_name);
    if (!commit_message) {
        git_tree_free(new_tree);
        free(ref_name);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    err = gitops_create_commit(
        repo,
        profile_name,
        new_tree,
        commit_message,
        NULL
    );

    free(commit_message);
    git_tree_free(new_tree);
    free(ref_name);

    if (err) {
        return error_wrap(err, "Failed to commit bootstrap script");
    }

    return NULL;
}

/**
 * Edit bootstrap script
 */
static error_t *bootstrap_edit(
    git_repository *repo,
    const char *repo_dir,
    const char *profile_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(repo_dir);
    CHECK_NULL(profile_name);

    const char *script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;

    /* Create script if it doesn't exist */
    if (!bootstrap_exists(repo, profile_name, script_name)) {
        error_t *err = bootstrap_create_template(repo, repo_dir, profile_name, script_name);
        if (err) {
            return error_wrap(err, "Failed to create bootstrap template");
        }
        if (out) {
            output_success(out, "Created bootstrap script for profile '%s'", profile_name);
        }
    }

    /* Get script path */
    char *script_path = NULL;
    error_t *err = bootstrap_get_path(repo_dir, profile_name, script_name, &script_path);
    if (err) {
        return error_wrap(err, "Failed to get bootstrap script path");
    }

    /* Launch editor - priority: DOTTA_EDITOR, VISUAL, EDITOR, nano */
    err = editor_launch_with_env(script_path, "nano");
    free(script_path);

    if (err) {
        return error_wrap(err, "Failed to edit bootstrap script");
    }

    return NULL;
}

/**
 * Show bootstrap script content
 */
static error_t *bootstrap_show(
    git_repository *repo,
    const char *repo_dir,
    const char *profile_name,
    const char *script_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(repo_dir);
    CHECK_NULL(profile_name);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Check if script exists */
    if (!bootstrap_exists(repo, profile_name, script_name)) {
        return ERROR(ERR_NOT_FOUND,
                    "No bootstrap script found for profile '%s'", profile_name);
    }

    /* Get script path */
    char *script_path = NULL;
    error_t *err = bootstrap_get_path(repo_dir, profile_name, script_name, &script_path);
    if (err) {
        return error_wrap(err, "Failed to get bootstrap script path");
    }

    /* Read and display file */
    FILE *fp = fopen(script_path, "r");
    if (!fp) {
        free(script_path);
        return ERROR(ERR_FS, "Failed to open bootstrap script");
    }

    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        if (out) {
            output_printf(out, OUTPUT_NORMAL, "%s", buf);
        }
    }

    fclose(fp);
    free(script_path);
    return NULL;
}

/**
 * List bootstrap scripts for profiles
 */
static error_t *bootstrap_list(
    git_repository *repo,
    const char *repo_dir,
    struct profile_list *profiles,
    const char *script_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(repo_dir);
    CHECK_NULL(profiles);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    profile_list_t *plist = (profile_list_t *)profiles;

    if (out) {
        output_section(out, "Bootstrap scripts");

        for (size_t i = 0; i < plist->count; i++) {
            profile_t *profile = &plist->profiles[i];
            bool exists = bootstrap_exists(repo, profile->name, script_name);

            if (exists) {
                char *script_path = NULL;
                error_t *err = bootstrap_get_path(repo_dir, profile->name, script_name, &script_path);
                if (err) {
                    error_free(err);
                    output_printf(out, OUTPUT_NORMAL, "  ✓ %-15s (path error)\n", profile->name);
                } else {
                    output_printf(out, OUTPUT_NORMAL, "  ✓ %-15s %s\n", profile->name, script_path);
                    free(script_path);
                }
            } else {
                output_printf(out, OUTPUT_NORMAL, "  ✗ %-15s (no bootstrap script)\n", profile->name);
            }
        }

        output_newline(out);
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "%sHint: Create a bootstrap script with:%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s  dotta bootstrap --profile <profile> --edit%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_info(out, "Hint: Create a bootstrap script with:");
            output_info(out, "  dotta bootstrap --profile <profile> --edit");
        }
    }

    return NULL;
}

/**
 * Execute bootstrap command
 */
error_t *cmd_bootstrap(const cmd_bootstrap_options_t *opts) {
    CHECK_NULL(opts);

    error_t *err = NULL;
    git_repository *repo = NULL;
    char *repo_path = NULL;
    profile_list_t *profiles = NULL;
    dotta_config_t *config = NULL;
    output_ctx_t *out = NULL;

    /* Load config */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal - use defaults */
        error_free(err);
        config = config_create_default();
    }

    /* Create output context from config */
    out = output_create_from_config(config);
    if (!out) {
        err = ERROR(ERR_MEMORY, "Failed to create output context");
        goto cleanup;
    }

    /* Resolve repository path */
    err = resolve_repo_path(&repo_path);
    if (err) {
        err = error_wrap(err, "Failed to resolve repository path");
        goto cleanup;
    }

    /* Check if repository exists */
    if (!gitops_is_repository(repo_path)) {
        err = ERROR(ERR_NOT_FOUND,
                   "No dotta repository found at: %s\n"
                   "Run 'dotta init' to create a new repository or 'dotta clone' to clone an existing one",
                   repo_path);
        goto cleanup;
    }

    /* Open repository */
    err = gitops_open_repository(&repo, repo_path);
    if (err) {
        err = error_wrap(err, "Failed to open repository");
        goto cleanup;
    }

    /* Handle --edit flag */
    if (opts->edit) {
        /* Check profile count */
        if (opts->profile_count > 1) {
            err = ERROR(ERR_INVALID_ARG, "Can only edit one profile at a time");
            goto cleanup;
        }

        /* Default to 'global' profile if none specified */
        const char *profile_to_edit = (opts->profile_count == 0) ? "global" : opts->profiles[0];

        /* Edit the bootstrap script */
        err = bootstrap_edit(repo, repo_path, profile_to_edit, out);
        if (err) {
            err = error_wrap(err, "Failed to edit bootstrap script");
        }
        goto cleanup;
    }

    /* Resolve profiles */
    if (opts->profile_count > 0) {
        /* Use explicitly specified profiles */
        err = profile_list_load(repo, opts->profiles, opts->profile_count,
                               true, &profiles);
        if (err) {
            err = error_wrap(err, "Failed to load profiles");
            goto cleanup;
        }
    } else if (opts->all_profiles) {
        /* List all local profiles */
        err = profile_list_all_local(repo, &profiles);
        if (err) {
            err = error_wrap(err, "Failed to list all profiles");
            goto cleanup;
        }
    } else {
        /* Auto-detect profiles */
        err = profile_detect_auto(repo, &profiles);
        if (err) {
            err = error_wrap(err, "Failed to auto-detect profiles");
            goto cleanup;
        }

        if (profiles->count == 0) {
            output_info(out, "No profiles detected for this machine.");
            output_newline(out);
            if (output_colors_enabled(out)) {
                output_printf(out, OUTPUT_NORMAL, "%sHint: Create a profile with:%s\n",
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             output_color_code(out, OUTPUT_COLOR_RESET));
                output_printf(out, OUTPUT_NORMAL, "%s  dotta add --profile <profile-name> <file>%s\n",
                             output_color_code(out, OUTPUT_COLOR_DIM),
                             output_color_code(out, OUTPUT_COLOR_RESET));
            } else {
                output_info(out, "Hint: Create a profile with:");
                output_info(out, "  dotta add --profile <profile-name> <file>");
            }
            goto cleanup;
        }
    }

    /* Handle --list flag */
    if (opts->list) {
        err = bootstrap_list(repo, repo_path, (struct profile_list *)profiles, NULL, out);
        if (err) {
            err = error_wrap(err, "Failed to list bootstrap scripts");
        }
        goto cleanup;
    }

    /* Handle --show flag */
    if (opts->show) {
        /* Check profile count */
        if (opts->profile_count > 1) {
            err = ERROR(ERR_INVALID_ARG, "Can only show one profile at a time");
            goto cleanup;
        }

        /* Default to 'global' profile if none specified */
        const char *profile_to_show = (opts->profile_count == 0) ? "global" : opts->profiles[0];

        /* Show the bootstrap script */
        err = bootstrap_show(repo, repo_path, profile_to_show, NULL, out);
        if (err) {
            err = error_wrap(err, "Failed to show bootstrap script");
        }
        goto cleanup;
    }

    /* Count bootstrap scripts that exist */
    size_t script_count = 0;
    for (size_t i = 0; i < profiles->count; i++) {
        if (bootstrap_exists(repo, profiles->profiles[i].name, NULL)) {
            script_count++;
        }
    }

    if (script_count == 0) {
        output_info(out, "No bootstrap scripts found in selected profiles.");
        output_newline(out);
        output_section(out, "Profiles checked");
        for (size_t i = 0; i < profiles->count; i++) {
            output_printf(out, OUTPUT_NORMAL, "  - %s\n", profiles->profiles[i].name);
        }
        output_newline(out);
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "%sHint: Create a bootstrap script with:%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s  dotta bootstrap --profile <profile> --edit%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_info(out, "Hint: Create a bootstrap script with:");
            output_info(out, "  dotta bootstrap --profile <profile> --edit");
        }
        goto cleanup;
    }

    /* Display what will be executed */
    output_section(out, "Found bootstrap scripts");
    for (size_t i = 0; i < profiles->count; i++) {
        if (bootstrap_exists(repo, profiles->profiles[i].name, NULL)) {
            output_printf(out, OUTPUT_NORMAL, "  ✓ %s/.dotta/bootstrap\n", profiles->profiles[i].name);
        }
    }
    output_newline(out);

    /* Prompt for confirmation unless --yes or --dry-run */
    if (!opts->yes && !opts->dry_run) {
        bool confirmed = output_confirm(out, "Would you like to execute bootstrap scripts now?", false);
        if (!confirmed) {
            output_info(out, "Bootstrap cancelled.");
            goto cleanup;
        }
    }

    /* Execute bootstrap scripts */
    bool stop_on_error = !opts->continue_on_error;
    err = bootstrap_run_for_profiles(repo, repo_path,
                                     (struct profile_list *)profiles,
                                     opts->dry_run, stop_on_error);
    if (err) {
        err = error_wrap(err, "Bootstrap failed");
        goto cleanup;
    }

    if (!opts->dry_run) {
        output_newline(out);
        output_success(out, "Bootstrap complete!");
        output_newline(out);
        if (output_colors_enabled(out)) {
            output_printf(out, OUTPUT_NORMAL, "%sNext steps:%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s  dotta apply            # Apply profiles to your system%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
            output_printf(out, OUTPUT_NORMAL, "%s  dotta status           # View current state%s\n",
                         output_color_code(out, OUTPUT_COLOR_DIM),
                         output_color_code(out, OUTPUT_COLOR_RESET));
        } else {
            output_info(out, "Next steps:");
            output_info(out, "  dotta apply            # Apply profiles to your system");
            output_info(out, "  dotta status           # View current state");
        }
    }

cleanup:
    if (profiles) profile_list_free(profiles);
    if (repo) gitops_close_repository(repo);
    if (repo_path) free(repo_path);
    if (out) output_free(out);
    if (config) config_free(config);
    return err;
}
