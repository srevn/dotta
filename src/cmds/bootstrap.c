/**
 * bootstrap.c - Bootstrap command implementation
 */

#include "cmds/bootstrap.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/output.h"
#include "base/string.h"
#include "core/profiles.h"
#include "sys/bootstrap.h"
#include "sys/editor.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/repo.h"

/* Bootstrap script template */
static const char *BOOTSTRAP_TEMPLATE =
    "#!/usr/bin/env bash\n"
    "#\n"
    "# Bootstrap script for %s profile\n"
    "#\n"
    "# This script runs after cloning the repository and before applying profiles.\n"
    "# Use it to install dependencies, set up package managers, or configure the system.\n"
    "#\n"
    "# Working directory: $HOME (your home directory)\n"
    "#   Access the dotta repository via: $DOTTA_REPO_DIR\n"
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
 *
 * Creates a bootstrap script directly in the Git tree without writing to filesystem.
 */
static error_t *bootstrap_create_template(
    git_repository *repo,
    const char *profile_name,
    const char *script_name
) {
    CHECK_NULL(repo);
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
        return ERROR(
            ERR_NOT_FOUND, "Profile '%s' does not exist",
            profile_name
        );
    }

    /* Check if script already exists in Git */
    if (bootstrap_exists(repo, profile_name, script_name)) {
        return ERROR(
            ERR_EXISTS, "Bootstrap script already exists for profile '%s'",
            profile_name
        );
    }

    /* Generate template content */
    char *content = str_format(
        BOOTSTRAP_TEMPLATE, profile_name, profile_name, profile_name
    );
    if (!content) {
        return ERROR(ERR_MEMORY, "Failed to generate bootstrap template");
    }
    size_t content_len = strlen(content);

    /* Create commit */
    char *commit_message = str_format(
        "Add bootstrap script for %s profile", profile_name
    );
    if (!commit_message) {
        free(content);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    /* Create bootstrap script in Git (atomic: blob + tree + commit) */
    err = gitops_update_file(
        repo,
        profile_name,
        script_name,
        content,
        content_len,
        commit_message,
        GIT_FILEMODE_BLOB_EXECUTABLE,
        NULL
    );

    free(content);
    free(commit_message);

    if (err) {
        return error_wrap(err, "Failed to commit bootstrap script");
    }

    return NULL;
}

/**
 * Edit bootstrap script
 *
 * Extracts the bootstrap script to a temporary file, opens it in an editor,
 * then commits the changes back to Git.
 */
static error_t *bootstrap_edit(
    git_repository *repo,
    const char *profile_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);

    const char *script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    error_t *err = NULL;
    char *temp_path = NULL;
    buffer_t content_buf = BUFFER_INIT;
    char *commit_msg = NULL;

    /* Create script if it doesn't exist */
    if (!bootstrap_exists(repo, profile_name, script_name)) {
        err = bootstrap_create_template(repo, profile_name, script_name);
        if (err) {
            return error_wrap(
                err, "Failed to create bootstrap template"
            );
        }
        output_success(
            out, OUTPUT_NORMAL, "Created bootstrap script for profile '%s'",
            profile_name
        );
    }

    /* Extract script to temporary file for editing */
    err = bootstrap_extract_to_temp(repo, profile_name, script_name, &temp_path);
    if (err) {
        return error_wrap(err, "Failed to extract bootstrap script");
    }

    /* Launch editor - priority: DOTTA_EDITOR, VISUAL, EDITOR, nano */
    err = editor_launch_with_env(temp_path, "nano");
    if (err) {
        err = error_wrap(err, "Failed to edit bootstrap script");
        goto cleanup;
    }

    /* Read edited content back from temp file */
    err = fs_read_file(temp_path, &content_buf);
    if (err) {
        err = error_wrap(err, "Failed to read edited bootstrap script");
        goto cleanup;
    }

    /* Validate edited content before committing */
    if (content_buf.size == 0) {
        err = ERROR(ERR_INVALID_ARG, "Bootstrap script cannot be empty");
        goto cleanup;
    }

    err = bootstrap_validate_content((const unsigned char *) content_buf.data, content_buf.size);
    if (err) {
        err = error_wrap(err, "Edited bootstrap script has invalid content");
        goto cleanup;
    }

    /* Auto-commit the changes */
    commit_msg = str_format("Update bootstrap script for %s profile", profile_name);
    if (!commit_msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    bool was_modified = false;
    err = gitops_update_file(
        repo, profile_name, script_name, (const char *) content_buf.data,
        content_buf.size, commit_msg, GIT_FILEMODE_BLOB_EXECUTABLE,
        &was_modified
    );

    if (err) {
        err = error_wrap(err, "Failed to commit bootstrap script");
        goto cleanup;
    }

    /* Inform user */
    if (was_modified) {
        output_success(
            out, OUTPUT_NORMAL, "Updated and committed bootstrap script for profile '%s'",
            profile_name
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL, "No changes made to bootstrap script"
        );
    }

    err = NULL;

cleanup:
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    buffer_free(&content_buf);
    if (commit_msg) free(commit_msg);

    return err;
}

/**
 * Show bootstrap script content
 *
 * Reads and displays the bootstrap script content from Git.
 */
static error_t *bootstrap_show(
    git_repository *repo,
    const char *profile_name,
    const char *script_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_name);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    /* Check if script exists */
    if (!bootstrap_exists(repo, profile_name, script_name)) {
        return ERROR(
            ERR_NOT_FOUND, "No bootstrap script found for profile '%s'",
            profile_name
        );
    }

    /* Read content from Git blob */
    buffer_t content = BUFFER_INIT;
    error_t *err = bootstrap_read_content(
        repo, profile_name, script_name, &content
    );
    if (err) {
        return error_wrap(err, "Failed to read bootstrap script");
    }

    /* Display content */
    if (out && content.size > 0) {
        /* Write content as a single block (includes newlines) */
        output_print(
            out, OUTPUT_NORMAL, "%.*s",
            (int) content.size, (const char *) content.data
        );
    }

    buffer_free(&content);

    return NULL;
}

/**
 * List bootstrap scripts for profiles
 */
static error_t *bootstrap_list(
    git_repository *repo,
    const char *const *profile_names,
    size_t profile_count,
    const char *script_name,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile_names);

    if (!script_name) {
        script_name = BOOTSTRAP_DEFAULT_SCRIPT_NAME;
    }

    if (out) {
        output_section(out, OUTPUT_NORMAL, "Bootstrap scripts");

        for (size_t i = 0; i < profile_count; i++) {
            const char *name = profile_names[i];
            bool exists = bootstrap_exists(repo, name, script_name);

            if (exists) {
                output_styled(
                    out, OUTPUT_NORMAL,
                    "  {green}✓{reset} %-15s %s/%s\n",
                    name, name, script_name
                );
            } else {
                output_styled(
                    out, OUTPUT_NORMAL,
                    "  {red}✗{reset} %-15s (no bootstrap script)\n",
                    name
                );
            }
        }

        output_newline(out, OUTPUT_NORMAL);
        output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
        output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap --profile <profile> --edit");
    }

    return NULL;
}

/**
 * Execute bootstrap command
 */
error_t *cmd_bootstrap(
    const config_t *config,
    output_ctx_t *out,
    const cmd_bootstrap_options_t *opts
) {
    CHECK_NULL(config);
    CHECK_NULL(opts);

    error_t *err = NULL;
    git_repository *repo = NULL;
    char *repo_path = NULL;
    string_array_t *profile_names = NULL;

    /* Resolve repository path */
    err = resolve_repo_path(config, &repo_path);
    if (err) {
        err = error_wrap(err, "Failed to resolve repository path");
        goto cleanup;
    }

    /* Check if repository exists */
    if (!gitops_is_repository(repo_path)) {
        err = ERROR(
            ERR_NOT_FOUND, "No dotta repository found at: %s\n"
            "Run 'dotta init' to create a new repository or "
            "'dotta clone' to clone an existing one", repo_path
        );
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
            err = ERROR(
                ERR_INVALID_ARG, "Can only edit one profile at a time"
            );
            goto cleanup;
        }

        /* Default to 'global' profile if none specified */
        const char *profile_to_edit = (opts->profile_count == 0)
                                    ? "global" : opts->profiles[0];

        /* Edit the bootstrap script */
        err = bootstrap_edit(repo, profile_to_edit, out);
        if (err) {
            err = error_wrap(err, "Failed to edit bootstrap script");
        }
        goto cleanup;
    }

    /* Resolve profile names — all branches produce string_array_t (name-only).
     * Bootstrap never needs full profile_t structs (Git refs, trees). */
    if (opts->profile_count > 0) {
        /* Explicit profiles: validate branch existence */
        err = profile_resolve_cli_names(
            repo, opts->profiles, opts->profile_count, true, &profile_names
        );
        if (err) {
            err = error_wrap(err, "Failed to resolve profiles");
            goto cleanup;
        }
    } else if (opts->all_profiles) {
        /* List all local profile names (lightweight, no ref resolution) */
        err = profile_list_all_local_names(repo, &profile_names);
        if (err) {
            err = error_wrap(err, "Failed to list all profiles");
            goto cleanup;
        }
    } else {
        /* Use enabled profiles from state */
        err = profile_resolve_state_names(repo, &profile_names);
        if (err) {
            if (error_code(err) == ERR_NOT_FOUND) {
                /* No profiles enabled — expected case, show guidance */
                output_info(out, OUTPUT_NORMAL, "No enabled profiles found.");
                output_hint(out, OUTPUT_NORMAL, "Enable profiles first:");
                output_hintline(out, OUTPUT_NORMAL, "  dotta profile enable <name>");
                error_free(err);
                err = NULL;
            }
            /* Other errors (corrupted state, permission, etc.) propagate */
            goto cleanup;
        }
    }

    /* Handle --list flag */
    if (opts->list) {
        err = bootstrap_list(
            repo, (const char *const *) profile_names->items,
            profile_names->count, NULL, out
        );
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
        const char *profile_to_show = (opts->profile_count == 0)
                                    ? "global" : opts->profiles[0];

        /* Show the bootstrap script */
        err = bootstrap_show(repo, profile_to_show, NULL, out);
        if (err) {
            err = error_wrap(err, "Failed to show bootstrap script");
        }
        goto cleanup;
    }

    /* Count bootstrap scripts that exist */
    size_t script_count = 0;
    for (size_t i = 0; i < profile_names->count; i++) {
        if (bootstrap_exists(repo, profile_names->items[i], NULL)) {
            script_count++;
        }
    }

    if (script_count == 0) {
        output_info(out, OUTPUT_NORMAL, "No bootstrap scripts found in enabled profiles.");
        output_newline(out, OUTPUT_NORMAL);
        output_section(out, OUTPUT_NORMAL, "Profiles checked");

        for (size_t i = 0; i < profile_names->count; i++) {
            output_print(out, OUTPUT_NORMAL, "  - %s\n", profile_names->items[i]);
        }
        output_newline(out, OUTPUT_NORMAL);
        output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
        output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap --profile <profile> --edit");
        goto cleanup;
    }

    /* Display what will be executed */
    output_section(out, OUTPUT_NORMAL, "Found bootstrap scripts");
    for (size_t i = 0; i < profile_names->count; i++) {
        if (bootstrap_exists(repo, profile_names->items[i], NULL)) {
            output_styled(
                out, OUTPUT_NORMAL, "  {green}✓{reset} %s/.bootstrap\n",
                profile_names->items[i]
            );
        }
    }
    output_newline(out, OUTPUT_NORMAL);

    /* Prompt for confirmation unless --yes or --dry-run */
    if (!opts->yes && !opts->dry_run) {
        bool confirmed = output_confirm(
            out, "Would you like to execute bootstrap scripts now?", false
        );

        if (!confirmed) {
            output_info(out, OUTPUT_NORMAL, "Bootstrap cancelled.");
            goto cleanup;
        }
    }

    /* Execute bootstrap scripts */
    bool stop_on_error = !opts->continue_on_error;
    bool had_failures = false;
    err = bootstrap_run_for_profiles(
        repo, repo_path, (const char *const *) profile_names->items,
        profile_names->count, opts->dry_run, stop_on_error
    );
    if (err) {
        if (opts->continue_on_error) {
            /* Partial failure — details already printed to stderr */
            had_failures = true;
            error_free(err);
            err = NULL;
        } else {
            err = error_wrap(err, "Bootstrap failed");
            goto cleanup;
        }
    }

    if (!opts->dry_run) {
        output_newline(out, OUTPUT_NORMAL);
        if (had_failures) {
            output_warning(out, OUTPUT_NORMAL, "Bootstrap completed with errors.");
        } else {
            output_success(out, OUTPUT_NORMAL, "Bootstrap complete!");
        }
        output_newline(out, OUTPUT_NORMAL);
        output_hintline(out, OUTPUT_NORMAL, "Next steps:");
        output_hintline(out, OUTPUT_NORMAL, "  Apply profiles:  dotta apply");
        output_hintline(out, OUTPUT_NORMAL, "  View state:      dotta status");
    }

cleanup:
    if (profile_names) string_array_free(profile_names);
    if (repo) gitops_close_repository(repo);
    if (repo_path) free(repo_path);

    return err;
}
