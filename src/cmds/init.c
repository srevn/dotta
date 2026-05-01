/**
 * init.c - Initialize dotta repository
 */

#include "cmds/init.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "core/ignore.h"
#include "core/state.h"
#include "infra/salt.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "utils/repo.h"

/**
 * Initialize repository
 *
 * @param path Repository path
 * @param out Repository handle
 * @param is_new Set to true if a new repo was created, false if existing
 */
static error_t *init_repository(const char *path, git_repository **out, bool *is_new) {
    CHECK_NULL(path);
    CHECK_NULL(out);
    CHECK_NULL(is_new);

    git_repository *repo = NULL;
    int err;

    /* Try to open existing repository first */
    err = git_repository_open(&repo, path);
    if (err == 0) {
        /* Repository already exists */
        *out = repo;
        *is_new = false;
        return NULL;
    }

    /* Create new repository */
    git_repository_init_options opts;
    git_repository_init_options_init(&opts, GIT_REPOSITORY_INIT_OPTIONS_VERSION);
    opts.flags = GIT_REPOSITORY_INIT_MKPATH;

    err = git_repository_init_ext(&repo, path, &opts);
    if (err < 0) {
        return error_from_git(err);
    }

    *out = repo;
    *is_new = true;

    return NULL;
}

/**
 * Ensure the dotta-worktree branch exists and HEAD points at it.
 *
 * Idempotent across self-healing re-init: the orphan commit is only
 * created when the branch is absent. Recreating an existing branch
 * would silently overwrite its history — including any user-customised
 * baseline `.dottaignore` blob — which is the bug the old
 * `is_initialized` short-circuit was guarding against. The guard now
 * lives here, where it is precisely scoped to the destructive step.
 *
 * `set_head` runs unconditionally so a partial prior init that left
 * HEAD on a profile branch (or on the freshly-init'd repo's default
 * `main`) gets corrected. The call is a no-op when HEAD already
 * targets dotta-worktree.
 *
 * Worktree-sync strategy:
 *   - Branch just created on a brand-new repo: FORCE — there is no
 *     user data anywhere to lose.
 *   - Any other case (healing path, or fresh creation in a pre-
 *     existing git repo): SAFE — local workdir modifications abort
 *     the checkout cleanly with an actionable error.
 */
static error_t *ensure_worktree_branch(git_repository *repo, bool is_new_repo) {
    CHECK_NULL(repo);

    bool exists = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", &exists);
    if (err) {
        return error_wrap(err, "Failed to check for dotta-worktree branch");
    }

    bool just_created = false;
    if (!exists) {
        err = gitops_create_orphan_branch(repo, "dotta-worktree");
        if (err) {
            return error_wrap(err, "Failed to create dotta-worktree branch");
        }
        just_created = true;
    }

    /* Set HEAD to dotta-worktree */
    int git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Sync working directory with the (empty) dotta-worktree branch */
    git_checkout_strategy_t strategy = (just_created && is_new_repo)
        ? GIT_CHECKOUT_FORCE
        : GIT_CHECKOUT_SAFE;

    err = gitops_sync_worktree(repo, strategy);
    if (err) {
        return error_wrap(err, "Failed to checkout dotta-worktree");
    }

    return NULL;
}

/**
 * Initialize state file
 *
 * Opens a write-locked handle, which creates .git/dotta.db with the schema
 * if it does not already exist, then commits the empty transaction. A clean
 * state file on disk means subsequent commands do not have to bootstrap it.
 */
static error_t *init_state(git_repository *repo) {
    CHECK_NULL(repo);

    state_t *state = NULL;
    error_t *err = state_open(repo, &state);
    if (err) {
        return err;
    }

    err = state_save(repo, state);
    state_free(state);

    if (err) {
        return error_wrap(err, "Failed to save initial state");
    }

    return NULL;
}

/**
 * Initialize command implementation
 */
error_t *cmd_init(const dotta_ctx_t *ctx, const cmd_init_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    git_repository *repo = NULL;
    error_t *err = NULL;
    char *resolved_path = NULL;
    const char *path = NULL;

    /* Handle quiet flag */
    if (opts->quiet) {
        output_set_verbosity(out, OUTPUT_QUIET);
    }

    /* Determine repository path */
    if (opts->repo_path) {
        /* User provided explicit path */
        path = opts->repo_path;
    } else {
        /* Use resolved repository location */
        err = resolve_repo_path(config, &resolved_path);
        if (err) {
            err = error_wrap(err, "Failed to resolve repository path");
            goto cleanup;
        }
        path = resolved_path;

        /* Ensure parent directories exist */
        err = fs_ensure_parent_dirs(path);
        if (err) {
            err = error_wrap(err, "Failed to create parent directories");
            goto cleanup;
        }
    }

    /* Initialize or open repository */
    bool is_new_repo = false;
    err = init_repository(path, &repo, &is_new_repo);
    if (err) {
        err = error_wrap(err, "Failed to initialize repository");
        goto cleanup;
    }

    /*
     * Idempotent setup. Each step is safe to re-run on an existing
     * repository: a fully-healthy repo no-ops at every step, and a
     * partial prior init.
     */

    /* dotta-worktree branch + HEAD */
    err = ensure_worktree_branch(repo, is_new_repo);
    if (err) {
        goto cleanup;
    }

    /* state.db schema (state_open creates if missing) */
    err = init_state(repo);
    if (err) {
        goto cleanup;
    }

    /* Per-repo Argon2id salt at refs/dotta/salt. Idempotent — keeps
     * an existing valid blob; surfaces a malformed blob as an error
     * rather than overwriting it. Done unconditionally (not gated on
     * encryption_enabled) so a later `dotta key set` finds the salt
     * ready, and so `dotta clone` of this repo can fetch the salt
     * regardless of the cloner's config. */
    err = salt_init(repo);
    if (err) {
        err = error_wrap(err, "Failed to initialize repository salt");
        goto cleanup;
    }

    /* Baseline .dottaignore on dotta-worktree. Idempotent —
     * gitops_update_file no-ops on identical content. */
    err = ignore_seed_baseline(repo);
    if (err) {
        err = error_wrap(err, "Failed to seed baseline .dottaignore");
        goto cleanup;
    }

    /* Success */
    output_success(out, OUTPUT_NORMAL, "Initialized dotta repository in %s", path);
    output_newline(out, OUTPUT_NORMAL);

    output_hintline(out, OUTPUT_NORMAL, "Next steps:");
    output_hintline(out, OUTPUT_NORMAL, "  Create profile: dotta add --profile global ~/.bashrc");
    output_hintline(out, OUTPUT_NORMAL, "  Apply profiles: dotta apply");

cleanup:
    if (repo) git_repository_free(repo);
    if (resolved_path) free(resolved_path);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

static error_t *init_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_init(ctx, (const cmd_init_options_t *) opts_v);
}

static const args_opt_t init_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_FLAG(
        "q quiet",
        cmd_init_options_t,quiet,
        "Suppress output"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "[path]",
        cmd_init_options_t,repo_path,
        "Repository location (default: system default)"
    ),
    ARGS_END
};

const args_command_t spec_init = {
    .name        = "init",
    .summary     = "Initialize a new dotta repository",
    .usage       = "%s init [options] [path]",
    .description =
        "Create an empty Git repository wired for dotta profiles. The\n"
        "repository path defaults to $DOTTA_REPO_DIR, then the path\n"
        "configured in config.toml, then the per-user default directory.\n",
    .examples    =
        "  %s init                    # Default location\n"
        "  %s init ~/dotfiles         # Custom path\n"
        "  %s init --quiet            # No progress output\n",
    .epilogue    =
        "See also:\n"
        "  %s add <profile> <file>    # Create and populate a profile\n"
        "  %s apply                   # Deploy enabled profiles\n",
    .opts_size   = sizeof(cmd_init_options_t),
    .opts        = init_opts,
    .payload     = &dotta_ext_none,
    .dispatch    = init_dispatch,
};
