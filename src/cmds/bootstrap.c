/**
 * bootstrap.c - Bootstrap command implementation
 */

#include "cmds/bootstrap.h"

#include <config.h>
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
#include "base/heap.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "core/profiles.h"
#include "sys/bootstrap.h"
#include "sys/editor.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/stage.h"
#include "utils/bootstrap.h"

/* Bootstrap script template */
static const char *const BOOTSTRAP_TEMPLATE =
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
 * Commits the default template directly into the profile's Git tree (no
 * working-tree write). The profile is here — cmd_bootstrap's selection required
 * it — and the call fails if a bootstrap script already exists for it.
 */
static error_t bootstrap_create_template(
    git_repository *repo,
    const char *profile
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    /* Check if script already exists in Git */
    if (bootstrap_exists(repo, profile)) {
        return ERROR(
            ERR_EXISTS, "Bootstrap script already exists for profile '%s'",
            profile
        );
    }

    /* The profile's stage: the script goes on it, executable, in one commit */
    char refname[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(refname, sizeof(refname), profile);
    if (err) return err;

    stage_t *stage = NULL;
    err = stage_open(repo, refname, &stage);
    if (err) {
        return error_wrap(err, "Failed to open profile '%s'", profile);
    }

    /* Generate template content */
    char *content = heap_str_format(BOOTSTRAP_TEMPLATE, profile, profile, profile);

    err = stage_put(
        stage, BOOTSTRAP_SCRIPT_NAME, content, strlen(content),
        GIT_FILEMODE_BLOB_EXECUTABLE, NULL
    );
    free(content);
    if (err) {
        stage_free(stage);
        return err;
    }

    char *commit_message = heap_str_format(
        "Add bootstrap script for %s profile", profile
    );

    err = stage_commit(stage, commit_message, NULL);
    free(commit_message);
    stage_free(stage);
    if (err) {
        return error_wrap(err, "Failed to commit bootstrap script");
    }

    return NULL;
}

/**
 * Edit bootstrap script.
 *
 * Extracts the script to a temporary file, hands it to the user's editor, validates
 * the edited content, and commits the result back to Git. If the profile has no
 * script yet, one is created from the template first.
 */
static error_t bootstrap_edit(
    git_repository *repo,
    const char *profile,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profile);

    error_t err = NULL;
    char *temp_path = NULL;
    buffer_t content_buf = BUFFER_INIT;
    char *commit_msg = NULL;
    stage_t *stage = NULL;

    /* Create the script from the template if none exists yet. */
    if (!bootstrap_exists(repo, profile)) {
        err = bootstrap_create_template(repo, profile);
        if (err) return err;
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

    /* The user's editor: DOTTA_EDITOR, VISUAL, EDITOR, then vi (sys/editor.h) */
    err = editor_launch_with_env(temp_path);
    if (err) goto cleanup;   /* the editor's refusal names itself */

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
    commit_msg = heap_str_format(
        "Update bootstrap script for %s profile", profile
    );

    /* The edited script onto the profile's stage; the stage commits only a tree
     * that differs from the branch's, and says which. */
    char refname[DOTTA_REFNAME_MAX];
    err = gitops_branch_refname(refname, sizeof(refname), profile);
    if (err) goto cleanup;

    err = stage_open(repo, refname, &stage);
    if (err) {
        err = error_wrap(err, "Failed to open profile '%s'", profile);
        goto cleanup;
    }

    err = stage_put(
        stage, BOOTSTRAP_SCRIPT_NAME, content_buf.data, content_buf.size,
        GIT_FILEMODE_BLOB_EXECUTABLE, NULL
    );
    if (err) goto cleanup;

    bool was_modified = false;
    err = stage_commit(stage, commit_msg, &was_modified);
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
    buffer_deinit(&content_buf);
    free(commit_msg);
    stage_free(stage);
    return err;
}

/**
 * Show bootstrap script content.
 *
 * Reads the script from Git and writes its bytes to `out`.
 */
static error_t bootstrap_show(
    git_repository *repo,
    const char *profile,
    output_t *out
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
    error_t err = bootstrap_read(repo, profile, &content);
    if (err) {
        return error_wrap(err, "Failed to read bootstrap script");
    }

    /* Display content: a payload, the script's bytes as they are */
    if (content.size > 0) {
        output_write(
            out, OUTPUT_NORMAL, OUTPUT_COLOR_RESET, (const char *) content.data,
            content.size
        );
    }

    buffer_deinit(&content);
    return NULL;
}

/**
 * List bootstrap scripts across profiles.
 *
 * For each profile: green ✓ with path if the script exists, red ✗ otherwise.
 * Closes with a hint about how to create one.
 */
static void bootstrap_list(
    git_repository *repo,
    const string_array_t *profiles,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(profiles);

    output_section(out, OUTPUT_NORMAL, "Bootstrap scripts");

    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->entries[i];
        if (bootstrap_exists(repo, profile)) {
            output_print(
                out, OUTPUT_NORMAL,
                "  {green}✓{reset} %-15s %s/%s\n",
                profile, profile, BOOTSTRAP_SCRIPT_NAME
            );
        } else {
            output_print(
                out, OUTPUT_NORMAL,
                "  {red}✗{reset} %-15s (no bootstrap script)\n",
                profile
            );
        }
    }

    output_gap(out, OUTPUT_NORMAL);
    output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
    output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap <profile> --edit");
}

/**
 * Run the selection's scripts: the ones that stand, confirmed unless --yes or
 * --dry-run, fired in the selection's order (utils/bootstrap.h bootstrap_fire)
 */
static error_t bootstrap_run(
    const dotta_ctx_t *ctx,
    const cmd_bootstrap_options_t *opts,
    const string_array_t *profiles
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(profiles);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* Single-pass filter: collect profiles that actually have a script. Display
     * list and pass straight into bootstrap_fire — no double tree-walk. */
    string_array_t found;
    string_array_init(&found, ctx->arena);
    for (size_t i = 0; i < profiles->count; i++) {
        if (bootstrap_exists(repo, profiles->entries[i])) {
            string_array_push(&found, profiles->entries[i]);
        }
    }

    if (found.count == 0) {
        /* The set searched, as the line selected it */
        output_info(
            out, OUTPUT_NORMAL, opts->profile_count > 0
                ? "No bootstrap scripts found in the named profiles."
                : opts->all_profiles
                ? "No bootstrap scripts found in any profile."
                : "No bootstrap scripts found in enabled profiles."
        );
        output_section(out, OUTPUT_NORMAL, "Profiles checked");

        for (size_t i = 0; i < profiles->count; i++) {
            output_print(out, OUTPUT_NORMAL, "  - %s\n", profiles->entries[i]);
        }
        output_gap(out, OUTPUT_NORMAL);
        output_hint(out, OUTPUT_NORMAL, "Create a bootstrap script with:");
        output_hintline(out, OUTPUT_NORMAL, "  dotta bootstrap <profile> --edit");
        return NULL;
    }

    /* Display what will be executed */
    output_section(out, OUTPUT_NORMAL, "Found bootstrap scripts");
    for (size_t i = 0; i < found.count; i++) {
        output_print(
            out, OUTPUT_NORMAL, "  {green}✓{reset} %s/%s\n",
            found.entries[i], BOOTSTRAP_SCRIPT_NAME
        );
    }
    output_gap(out, OUTPUT_NORMAL);

    /* Prompt for confirmation unless --yes or --dry-run */
    if (!opts->yes && !opts->dry_run) {
        bool confirmed = output_confirm(out, false, "Execute bootstrap scripts?");
        if (!confirmed) {
            output_info(out, OUTPUT_NORMAL, "Bootstrap cancelled.");
            return NULL;
        }
    }

    bootstrap_spec_t spec = {
        .repo          = repo,
        .repo_dir      = ctx->config->repo_dir,
        .profiles      = &found,
        .dry_run       = opts->dry_run,
        .stop_on_error = !opts->continue_on_error,
    };

    /* What the run did: every failure a script's, its cause on its row as the
     * run went, so a refusal here restates none. A stop names where it stopped.
     * A run that went on past its failures has listed them as it closed
     * (bootstrap_fire), and counts them: a script the run tried and could not
     * finish is a broken promise whether or not the others ran — keeping going
     * is what --continue-on-error asks, as make -k does, never that a failure
     * is not one (cmds/profile.c profile_fetch keeps the same rule). */
    bootstrap_receipt_t receipt = bootstrap_fire(out, &spec);
    if (receipt.stopped) {
        return ERROR(
            ERR_INTERNAL, "Bootstrap stopped at profile '%s'", receipt.stopped
        );
    }
    if (receipt.failures > 0) {
        /* The plural agrees with the total, the noun it qualifies */
        return ERROR(
            ERR_INTERNAL, "%zu of %zu bootstrap script%s failed",
            receipt.failures, found.count, found.count == 1 ? "" : "s"
        );
    }

    if (!opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);
        output_success(out, OUTPUT_NORMAL, "Bootstrap complete!");
        output_gap(out, OUTPUT_NORMAL);
        output_hintline(out, OUTPUT_NORMAL, "Next steps:");
        output_hintline(out, OUTPUT_NORMAL, "  Apply profiles:  dotta apply");
        output_hintline(out, OUTPUT_NORMAL, "  View state:      dotta status");
    }

    return NULL;
}

/**
 * Execute bootstrap command
 */
error_t cmd_bootstrap(const dotta_ctx_t *ctx, const cmd_bootstrap_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    output_t *out = ctx->out;

    error_t err = NULL;

    /* The selection, its shape settled by the line (bootstrap_post_parse) and
     * read by name alone — a script is asked of a profile's name, never of its
     * tree. */
    string_array_t profiles;
    if (opts->profile_count > 0) {
        /* Explicit profiles: each must be here — a script asked for by a name
         * that is not a profile is a typo, not a skip */
        string_array_init_cap(&profiles, ctx->arena, opts->profile_count);
        for (size_t i = 0; i < opts->profile_count; i++) {
            err = profile_require(repo, opts->profiles[i]);
            if (err) return err;
            string_array_push(&profiles, opts->profiles[i]);
        }
    } else if (opts->all_profiles) {
        /* Every profile here, run in the convention's order: a set the machine
         * enumerated has no other, and a base's script belongs before its
         * variants'. Named profiles run in the order given; the enabled set below
         * runs in the machine's. */
        err = gitops_list_branches(repo, ctx->arena, &profiles);
        if (err) {
            return error_wrap(err, "Failed to list all profiles");
        }
        profile_order(&profiles);
    } else {
        /* Use enabled profiles from state */
        err = profile_resolve_enabled(repo, state, ctx->arena, &profiles);
        if (err) return err;

        /* No profiles enabled — expected case, show guidance */
        if (profiles.count == 0) {
            output_info(out, OUTPUT_NORMAL, "No enabled profiles found.");
            output_hint(out, OUTPUT_NORMAL, "Enable profiles first:");
            output_hintline(out, OUTPUT_NORMAL, "  dotta profile enable <name>");
            return NULL;
        }
    }

    /* The mode the line gave, one at most: a script edited or shown — the one
     * profile the line names — the selection's scripts listed, or run. The field
     * is an int for the engine's FLAG_SET, read as its enum so -Wswitch holds
     * every value named. */
    switch ((bootstrap_mode_t) opts->mode) {
        case BOOTSTRAP_MODE_EDIT:
            return bootstrap_edit(repo, profiles.entries[0], out);
        case BOOTSTRAP_MODE_SHOW:
            return bootstrap_show(repo, profiles.entries[0], out);
        case BOOTSTRAP_MODE_LIST:
            bootstrap_list(repo, &profiles, out);
            return NULL;
        case BOOTSTRAP_MODE_RUN:
            return bootstrap_run(ctx, opts, &profiles);
    }

    CHECK_ARG(false, "a bootstrap mode no enumerator names");
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * What can stand at the cursor: a local profile, by -p or bare — any profile's
 * script, enabled or not.
 */
static args_want_t bootstrap_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    (void) at;
    const dotta_ctx_t *ctx = ctx_v;

    completion_profiles(ctx, out, COMPLETION_LOCAL);
    return ARGS_WANT_NONE;
}

/**
 * The selection and the mode the line gives, settled before the store opens:
 * the profiles named or --all, never both, and a script edited or shown is one
 * named profile's. A second mode is the engine's to refuse: the three are one
 * FLAG_SET group. profile_post_parse refuses the same pair for profile's selection,
 * where naming none is refused too; here it is the enabled set.
 */
static error_t bootstrap_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_bootstrap_options_t *o = opts_v;

    if (o->all_profiles && o->profile_count > 0) {
        return ERROR(ERR_INVALID_ARG, "--all and profile names are mutually exclusive");
    }
    if (o->mode == BOOTSTRAP_MODE_EDIT && o->profile_count != 1) {
        return ERROR(ERR_INVALID_ARG, "--edit edits exactly one named profile's script");
    }
    return o->mode == BOOTSTRAP_MODE_SHOW && o->profile_count != 1
        ? ERROR(ERR_INVALID_ARG, "--show prints exactly one named profile's script")
        : NULL;
}

static error_t bootstrap_dispatch(const void *ctx_v, void *opts_v) {
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
    ARGS_FLAG_SET(
        "e edit",
        cmd_bootstrap_options_t,mode,              BOOTSTRAP_MODE_EDIT,
        "Edit one named profile's script"
    ),
    ARGS_FLAG_SET(
        "show",
        cmd_bootstrap_options_t,mode,              BOOTSTRAP_MODE_SHOW,
        "Print one named profile's script"
    ),
    ARGS_FLAG_SET(
        "l list",
        cmd_bootstrap_options_t,mode,              BOOTSTRAP_MODE_LIST,
        "List the selected profiles' scripts"
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
        "%s bootstrap [options] [<name>...]\n"
        "   or: %s bootstrap [options] --all\n"
        "   or: %s bootstrap --edit <name>\n"
        "   or: %s bootstrap --show <name>",
    .description =
        "Environment Variables:\n"
        "  DOTTA_REPO_DIR    Path to the dotta repository.\n"
        "  DOTTA_PROFILE     Current profile name.\n"
        "  DOTTA_PROFILES    Space-separated list of all profiles being bootstrapped.\n"
        "  HOME              User home directory.\n",
    .notes       =
        "Clone integration:\n"
        "  %s clone <url>                    # Prompts to run bootstrap\n"
        "  %s clone <url> --bootstrap        # Run without prompting\n"
        "  %s clone <url> --no-bootstrap     # Skip the check entirely\n"
        "\n"
        "Editor Selection (--edit):\n"
        "  $DOTTA_EDITOR, then $VISUAL, then $EDITOR, then vi.\n",
    .examples    =
        "  %s bootstrap                          # The enabled profiles\n"
        "  %s bootstrap darwin                   # Single profile\n"
        "  %s bootstrap darwin global            # Multiple profiles\n"
        "  %s bootstrap darwin --edit            # Edit darwin/.bootstrap\n"
        "  %s bootstrap --list                   # List available scripts\n"
        "  %s bootstrap darwin --show            # Print the script\n"
        "  %s bootstrap -n                       # Preview without running\n"
        "  %s bootstrap --yes                    # No prompts\n",
    .epilogue    =
        "See also:\n"
        "  %s apply                          # Deploy files after bootstrap\n",
    .opts_size   = sizeof(cmd_bootstrap_options_t),
    .opts        = bootstrap_opts,
    .post_parse  = bootstrap_post_parse,
    .complete    = bootstrap_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
    },
    .dispatch    = bootstrap_dispatch,
};
