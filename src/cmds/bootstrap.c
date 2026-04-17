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

#include "base/args.h"
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
#include "utils/bootstrap.h"

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
 * Create bootstrap script from template.
 *
 * Commits the default template directly into the profile's Git tree
 * (no working-tree write). Fails if the profile is missing or if a
 * bootstrap script already exists for it.
 */
static error_t *bootstrap_create_template(
    git_repository *repo,
    const char *profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    /* Check if profile exists */
    bool exists = false;
    error_t *err = gitops_branch_exists(repo, profile, &exists);
    if (err) {
        return error_wrap(err, "Failed to check if profile exists");
    }

    if (!exists) {
        return ERROR(
            ERR_NOT_FOUND, "Profile '%s' does not exist", profile
        );
    }

    /* Check if script already exists in Git */
    if (bootstrap_exists(repo, profile)) {
        return ERROR(
            ERR_EXISTS, "Bootstrap script already exists for profile '%s'",
            profile
        );
    }

    /* Generate template content */
    char *content = str_format(BOOTSTRAP_TEMPLATE, profile, profile, profile);
    if (!content) {
        return ERROR(ERR_MEMORY, "Failed to generate bootstrap template");
    }
    size_t content_len = strlen(content);

    /* Create commit */
    char *commit_message = str_format(
        "Add bootstrap script for %s profile", profile
    );
    if (!commit_message) {
        free(content);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    /* Create bootstrap script in Git (atomic: blob + tree + commit) */
    err = gitops_update_file(
        repo,
        profile,
        BOOTSTRAP_SCRIPT_NAME,
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
 * Edit bootstrap script.
 *
 * Extracts the script to a temporary file, hands it to the user's
 * editor, validates the edited content, and commits the result back
 * to Git. If the profile has no script yet, one is created from the
 * template first.
 */
static error_t *bootstrap_edit(
    git_repository *repo,
    const char *profile,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    error_t *err = NULL;
    char *temp_path = NULL;
    buffer_t content_buf = BUFFER_INIT;
    char *commit_msg = NULL;

    /* Create the script from the template if none exists yet. */
    if (!bootstrap_exists(repo, profile)) {
        err = bootstrap_create_template(repo, profile);
        if (err) {
            return error_wrap(err, "Failed to create bootstrap template");
        }
        output_success(
            out, OUTPUT_NORMAL,
            "Created bootstrap script for profile '%s'", profile
        );
    }

    /* Extract script to temporary file for editing */
    err = bootstrap_extract_to_temp(repo, profile, &temp_path);
    if (err) {
        return error_wrap(err, "Failed to extract bootstrap script");
    }

    /* Priority: DOTTA_EDITOR, VISUAL, EDITOR, nano. */
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

    err = bootstrap_validate(
        (const unsigned char *) content_buf.data, content_buf.size
    );
    if (err) {
        err = error_wrap(err, "Edited bootstrap script has invalid content");
        goto cleanup;
    }

    /* Auto-commit the changes */
    commit_msg = str_format(
        "Update bootstrap script for %s profile", profile
    );
    if (!commit_msg) {
        err = ERROR(ERR_MEMORY, "Failed to allocate commit message");
        goto cleanup;
    }

    bool was_modified = false;
    err = gitops_update_file(
        repo, profile, BOOTSTRAP_SCRIPT_NAME,
        (const char *) content_buf.data, content_buf.size,
        commit_msg, GIT_FILEMODE_BLOB_EXECUTABLE, &was_modified
    );
    if (err) {
        err = error_wrap(err, "Failed to commit bootstrap script");
        goto cleanup;
    }

    /* Inform user */
    if (was_modified) {
        output_success(
            out, OUTPUT_NORMAL,
            "Updated and committed bootstrap script for profile '%s'",
            profile
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL,
            "No changes made to bootstrap script"
        );
    }

    err = NULL;

cleanup:
    if (temp_path) {
        unlink(temp_path);
        free(temp_path);
    }
    buffer_free(&content_buf);
    free(commit_msg);
    return err;
}

/**
 * Show bootstrap script content.
 *
 * Reads the script from Git and writes its bytes to `out`.
 */
static error_t *bootstrap_show(
    git_repository *repo,
    const char *profile,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    if (!bootstrap_exists(repo, profile)) {
        return ERROR(
            ERR_NOT_FOUND, "No bootstrap script found for profile '%s'",
            profile
        );
    }

    /* Read content from Git blob */
    buffer_t content = BUFFER_INIT;
    error_t *err = bootstrap_read(repo, profile, &content);
    if (err) {
        return error_wrap(err, "Failed to read bootstrap script");
    }

    /* Display content */
    if (out && content.size > 0) {
        output_print(
            out, OUTPUT_NORMAL, "%.*s",
            (int) content.size, (const char *) content.data
        );
    }

    buffer_free(&content);
    return NULL;
}

/**
 * List bootstrap scripts across profiles.
 *
 * For each profile: green ✓ with path if the script exists, red ✗
 * otherwise. Closes with a hint about how to create one.
 */
static error_t *bootstrap_list(
    git_repository *repo,
    const string_array_t *profiles,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);

    if (!out) return NULL;

    output_section(out, OUTPUT_NORMAL, "Bootstrap scripts");

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];
        if (bootstrap_exists(repo, profile)) {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {green}✓{reset} %-15s %s/%s\n",
                profile, profile, BOOTSTRAP_SCRIPT_NAME
            );
        } else {
            output_styled(
                out, OUTPUT_NORMAL,
                "  {red}✗{reset} %-15s (no bootstrap script)\n",
                profile
            );
        }
    }

    output_newline(out, OUTPUT_NORMAL);
    output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
    output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap <profile> --edit");
    return NULL;
}

/**
 * Execute bootstrap command
 */
error_t *cmd_bootstrap(const dotta_ctx_t *ctx, const cmd_bootstrap_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const char *repo_path = ctx->repo_path;
    output_ctx_t *out = ctx->out;

    error_t *err = NULL;
    string_array_t *profiles = NULL;
    string_array_t found STRING_ARRAY_AUTO = { 0 };

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
     * Bootstrap only needs profile names, not Git trees. */
    if (opts->profile_count > 0) {
        /* Explicit profiles: validate branch existence */
        err = profile_resolve_filter(
            repo, opts->profiles, opts->profile_count, true, &profiles
        );
        if (err) {
            err = error_wrap(err, "Failed to resolve profiles");
            goto cleanup;
        }
    } else if (opts->all_profiles) {
        /* List all local profile names (lightweight, no ref resolution) */
        err = profile_list_all_local(repo, &profiles);
        if (err) {
            err = error_wrap(err, "Failed to list all profiles");
            goto cleanup;
        }
    } else {
        /* Use enabled profiles from state */
        err = profile_resolve_enabled(repo, NULL, &profiles);
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
        err = bootstrap_list(repo, profiles, out);
        if (err) {
            err = error_wrap(err, "Failed to list bootstrap scripts");
        }
        goto cleanup;
    }

    /* Handle --show flag */
    if (opts->show) {
        /* Check profile count */
        if (opts->profile_count > 1) {
            err = ERROR(
                ERR_INVALID_ARG, "Can only show one profile at a time"
            );
            goto cleanup;
        }

        /* Default to 'global' profile if none specified */
        const char *profile_to_show = (opts->profile_count == 0)
                                    ? "global" : opts->profiles[0];

        /* Show the bootstrap script */
        err = bootstrap_show(repo, profile_to_show, out);
        if (err) {
            err = error_wrap(err, "Failed to show bootstrap script");
        }
        goto cleanup;
    }

    /* Single-pass filter: collect profiles that actually have a
     * script. Display list and pass straight into bootstrap_fire —
     * no double tree-walk. */
    for (size_t i = 0; i < profiles->count; i++) {
        if (bootstrap_exists(repo, profiles->items[i])) {
            err = string_array_push(&found, profiles->items[i]);
            if (err) {
                err = error_wrap(err, "Failed to collect profiles");
                goto cleanup;
            }
        }
    }

    if (found.count == 0) {
        output_info(
            out, OUTPUT_NORMAL, "No bootstrap scripts found in enabled profiles."
        );
        output_newline(out, OUTPUT_NORMAL);
        output_section(out, OUTPUT_NORMAL, "Profiles checked");

        for (size_t i = 0; i < profiles->count; i++) {
            output_print(out, OUTPUT_NORMAL, "  - %s\n", profiles->items[i]);
        }
        output_newline(out, OUTPUT_NORMAL);
        output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
        output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap <profile> --edit");
        goto cleanup;
    }

    /* Display what will be executed */
    output_section(out, OUTPUT_NORMAL, "Found bootstrap scripts");
    for (size_t i = 0; i < found.count; i++) {
        output_styled(
            out, OUTPUT_NORMAL, "  {green}✓{reset} %s/%s\n",
            found.items[i], BOOTSTRAP_SCRIPT_NAME
        );
    }
    output_newline(out, OUTPUT_NORMAL);

    /* Prompt for confirmation unless --yes or --dry-run */
    if (!opts->yes && !opts->dry_run) {
        bool confirmed = output_confirm(out, "Execute bootstrap scripts?", false);
        if (!confirmed) {
            output_info(out, OUTPUT_NORMAL, "Bootstrap cancelled.");
            goto cleanup;
        }
    }

    bootstrap_spec_t spec = {
        .repo          = repo,
        .repo_dir      = repo_path,
        .profiles      = &found,
        .dry_run       = opts->dry_run,
        .stop_on_error = !opts->continue_on_error,
    };
    bool had_failures = false;

    err = bootstrap_fire(out, &spec);
    if (err) {
        if (opts->continue_on_error) {
            /* Partial failure — per-profile details already on screen
             * and the failed list was printed by bootstrap_fire. */
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
    if (profiles) string_array_free(profiles);
    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

static error_t *bootstrap_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_bootstrap(ctx, (const cmd_bootstrap_options_t *) opts_v);
}

static const args_opt_t bootstrap_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",            "<name>",
        cmd_bootstrap_options_t,profiles,          profile_count,
        "Filter to profile(s) (repeatable)"
    ),
    ARGS_FLAG(
        "all",
        cmd_bootstrap_options_t,all_profiles,
        "Run every available bootstrap script"
    ),
    ARGS_FLAG(
        "e edit",
        cmd_bootstrap_options_t,edit,
        "Edit the script (requires --profile)"
    ),
    ARGS_FLAG(
        "show",
        cmd_bootstrap_options_t,show,
        "Print the script (requires --profile)"
    ),
    ARGS_FLAG(
        "l list",
        cmd_bootstrap_options_t,list,
        "List all bootstrap scripts"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_bootstrap_options_t,dry_run,
        "Preview execution without running"
    ),
    ARGS_FLAG(
        "y yes no-confirm",
        cmd_bootstrap_options_t,yes,
        "Skip confirmation prompts"
    ),
    ARGS_FLAG(
        "continue-on-error",
        cmd_bootstrap_options_t,continue_on_error,
        "Continue after a script failure"
    ),
    /* Bare profile positionals funnel into the same APPEND field. */
    ARGS_POSITIONAL_ANY(
        cmd_bootstrap_options_t,profiles,          profile_count
    ),
    ARGS_END,
};

const args_command_t spec_bootstrap = {
    .name        = "bootstrap",
    .summary     = "Execute profile bootstrap scripts",
    .usage       =
        "%s bootstrap [options] [profile]...",
    .description =
        "Run the per-profile .bootstrap shell script, typically invoked\n"
        "once after clone to install dependencies and prepare the\n"
        "system. Without a positional, auto-detects profiles by\n"
        "resolution order.\n",
    .notes       =
        "Execution Order:\n"
        "  Scripts run in profile resolution order:\n"
        "    1. global/.bootstrap\n"
        "    2. <os>/.bootstrap (darwin, linux, freebsd)\n"
        "    3. hosts/<hostname>/.bootstrap\n"
        "\n"
        "Environment Variables:\n"
        "  DOTTA_REPO_DIR    Path to the dotta repository.\n"
        "  DOTTA_PROFILE     Current profile name.\n"
        "  DOTTA_PROFILES    Space-separated list of all active profiles.\n"
        "  HOME              User home directory.\n"
        "\n"
        "Bootstrap Script Location:\n"
        "  <repo>/<profile>/.bootstrap. Version-controlled; travels with\n"
        "  the profile.\n"
        "\n"
        "Editor Selection (--edit):\n"
        "  $DOTTA_EDITOR, then $VISUAL, then $EDITOR, then nano.\n",
    .examples    =
        "  %s bootstrap                          # Auto-detected profiles\n"
        "  %s bootstrap darwin                   # Single profile\n"
        "  %s bootstrap darwin global            # Multiple profiles\n"
        "  %s bootstrap darwin --edit            # Edit darwin/.bootstrap\n"
        "  %s bootstrap --list                   # List available scripts\n"
        "  %s bootstrap darwin --show            # Print the script\n"
        "  %s bootstrap -n                       # Preview without running\n"
        "  %s bootstrap --yes                    # No prompts\n",
    .epilogue    =
        "Clone integration:\n"
        "  %s clone <url>                    # Prompts to run bootstrap\n"
        "  %s clone <url> --bootstrap        # Run without prompting\n"
        "  %s clone <url> --no-bootstrap     # Skip the check entirely\n"
        "\n"
        "See also:\n"
        "  %s apply                          # Deploy files after bootstrap\n",
    .opts_size   = sizeof(cmd_bootstrap_options_t),
    .opts        = bootstrap_opts,
    .user_data   = &dotta_ext_required,
    .dispatch    = bootstrap_dispatch,
};
