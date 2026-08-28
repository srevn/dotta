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
 * May dotta make this repository its own?
 *
 * Everything below writes — HEAD moves, the working directory is checked out
 * against dotta-worktree's empty tree, a salt ref and a baseline `.dottaignore`
 * are committed. Right for dotta's repository, destructive for somebody else's,
 * so the question is asked once here, before the first of them, and answered
 * from refs alone: nothing on disk tells the two apart.
 *
 * Adoptable, cheapest test first:
 *
 *   is_new_repo             this run created it — no history to displace
 *   dotta-worktree exists   dotta's local marker, and `repo_open`'s own identity
 *                           test — the row that keeps its "Run 'dotta init'"
 *                           true when only the branch is gone
 *   refs/dotta/salt exists  dotta's synced marker, in a namespace nothing else
 *                           writes. Presence alone: a malformed salt is still
 *                           dotta's, and `salt_init` is what judges the payload
 *   no references at all    a bare `git init`. Untracked files are not history
 *                           and no step below touches them — the one that could,
 *                           the `.dottaignore` seed, adopts rather than overwrites
 *
 * Anything else holds a history dotta did not write. Warn-and-continue would be
 * worse than refusing: by the time a warning printed, HEAD would have moved. A
 * plain `git clone` of a dotta remote lands here too, and rightly — git never
 * fetches `refs/dotta`, and the clone is checked out on a profile branch. `dotta
 * clone` is the way in. `is_new_repo` being the first row is what keeps a refusal
 * from stranding a repository this run created.
 */
static error_t *ensure_repository_adoptable(
    git_repository *repo, const char *path, bool is_new_repo
) {
    CHECK_NULL(repo);
    CHECK_NULL(path);

    if (is_new_repo) {
        return NULL;
    }

    bool worktree_exists = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", &worktree_exists);
    if (err) {
        return error_wrap(err, "Failed to check for dotta-worktree branch");
    }
    if (worktree_exists) {
        return NULL;
    }

    git_reference *salt_ref = NULL;
    int git_err = git_reference_lookup(&salt_ref, repo, SALT_REF);
    if (git_err == 0) {
        git_reference_free(salt_ref);
        return NULL;
    }
    if (git_err != GIT_ENOTFOUND) {
        return error_wrap(
            error_from_git(git_err), "Failed to look up '%s'", SALT_REF
        );
    }

    /* Any reference at all is history this run did not write.
     * `git_repository_is_empty` answers a narrower question — it also requires
     * HEAD to name the configured initial branch, so `git init` followed by `git
     * checkout -b x` would fail it and be refused with nothing to lose. */
    git_strarray refs = { 0 };
    git_err = git_reference_list(&refs, repo);
    if (git_err < 0) {
        return error_wrap(
            error_from_git(git_err), "Failed to list repository references"
        );
    }
    size_t ref_count = refs.count;
    git_strarray_dispose(&refs);

    if (ref_count == 0) {
        return NULL;
    }

    return ERROR(
        ERR_CONFLICT,
        "'%s' is a Git repository that dotta did not create\n\n"
        "'dotta init' would move HEAD to 'dotta-worktree', check the working "
        "directory out against its empty tree, and commit a baseline "
        ".dottaignore there.\n\n"
        "Move the existing repository aside first, or point dotta elsewhere:\n"
        "  DOTTA_REPO_DIR=<path> dotta init\n"
        "  or set repo_dir under [core] in the config file",
        path
    );
}

/**
 * Ensure the dotta-worktree branch exists and HEAD points at it.
 *
 * Idempotent across self-healing re-init: the orphan commit is only created when
 * the branch is absent. Recreating an existing branch would silently overwrite
 * its history — including any user-customised baseline `.dottaignore` blob —
 * which is the bug the old `is_initialized` short-circuit was guarding against.
 * This is one of the two steps that short-circuit covered; the other is the
 * baseline seed, which guards itself (`ignore_seed_baseline`).
 *
 * `set_head` runs unconditionally so a partial prior init that left HEAD on a
 * profile branch (or on the freshly-init'd repo's default `main`) gets corrected.
 * The call is a no-op when HEAD already targets dotta-worktree.
 *
 * Worktree-sync strategy:
 *   - Branch just created on a brand-new repo: FORCE — there is no user data
 *     anywhere to lose.
 *   - Any other case (healing path, or fresh creation in a pre-existing git repo):
 *     SAFE — local workdir modifications abort the checkout cleanly with an
 *     actionable error.
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
 * Opens a write-locked handle, which creates .git/dotta.db with the schema if
 * it does not already exist, then commits the empty transaction. A clean state
 * file on disk means subsequent commands do not have to bootstrap it.
 */
static error_t *init_state(git_repository *repo) {
    CHECK_NULL(repo);

    state_t *state = NULL;
    error_t *err = state_open(repo, &state);
    if (err) {
        return err;
    }

    err = state_save(state);
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

    /* Whose repository is this? Asked before the first step below writes, so a
     * refusal leaves it exactly as it was found. */
    err = ensure_repository_adoptable(repo, path, is_new_repo);
    if (err) {
        goto cleanup;
    }

    /*
     * Idempotent setup. Each step is safe to re-run on an existing repository:
     * a fully-healthy repo no-ops at every step, and a partial prior init.
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

    /* Per-repo Argon2id salt at refs/dotta/salt. Idempotent — keeps an existing
     * valid blob; a malformed one is regenerated when the ciphertext census proves
     * nothing depends on it, and surfaced as an error otherwise. Done
     * unconditionally (not gated on encryption_enabled) so a later `dotta key
     * set` finds the salt ready, and so `dotta clone` of this repo can fetch
     * the salt regardless of the cloner's config. */
    bool salt_repaired = false;
    err = salt_init(repo, &salt_repaired);
    if (err) {
        /* ERR_CRYPTO here is the refusal to regenerate over reachable ciphertext:
         * the damaged ref may be the salt that keys it, so the fix is restoration,
         * never a fresh mint. */
        if (err->code == ERR_CRYPTO) {
            err = error_wrap(
                err,
                "Failed to initialize repository salt\n"
                "Hint: Encrypted data may depend on the damaged salt. If a "
                "remote holds the true salt, 'dotta sync' adopts it; otherwise "
                "restore refs/dotta/salt from a machine that has it."
            );
        } else {
            err = error_wrap(err, "Failed to initialize repository salt");
        }
        goto cleanup;
    }
    if (salt_repaired) {
        output_info(
            out, OUTPUT_NORMAL,
            "Repaired malformed repository salt (no encrypted data depended on it)"
        );
    }

    /* Baseline .dottaignore on dotta-worktree. Seeded once: a branch that already
     * carries the file keeps whatever the user made of it, and an untracked one
     * sitting at the repository root is adopted rather than overwritten. */
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

/**
 * What can stand at the cursor: the repository location, a directory, until one
 * is given.
 */
static args_want_t init_complete(
    const void *ctx, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) ctx;
    (void) at;
    (void) out;
    const cmd_init_options_t *o = opts_v;

    return o->repo_path == NULL ? ARGS_WANT_DIRS : ARGS_WANT_NONE;
}

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
        cmd_init_options_t,repo_path, 0,
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
    .notes       =
        "Existing Directories:\n"
        "  A directory holding a Git repository that dotta did not create is\n"
        "  refused: init would move its HEAD to dotta-worktree and leave its\n"
        "  files staged for deletion. An empty repository, or no repository\n"
        "  at all, is initialized in place; dotta's own is repaired in place.\n"
        "  An existing .dottaignore is never rewritten: one already on the\n"
        "  branch is kept, one sitting in the directory becomes the baseline.\n",
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
    .complete    = init_complete,
    .dispatch    = init_dispatch,
};
