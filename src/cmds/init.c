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
#include "crypto/kdf.h"
#include "infra/epoch.h"
#include "sys/gitops.h"
#include "utils/repo.h"

/**
 * May dotta make this repository its own?
 *
 * Everything below writes — the store's declaration, the record, an epoch ref,
 * a baseline ref. Right for dotta's store, destructive for somebody else's
 * repository, so the question is asked once here, before the first of them, and
 * a refusal leaves the repository exactly as it was found.
 *
 *   config unreadable        refused, the file named (utils/repo.h repo_is_store):
 *                            libgit2 reads the level it cannot open as absent,
 *                            core.bare with it, so every row below would answer
 *                            for a file nobody read
 *   not bare                 refused: dotta's store is bare (utils/repo.h), and a
 *                            working tree is somebody's — a project, or the store
 *                            an older dotta kept checked out. Nothing here
 *                            re-shapes one, declared or not.
 *   declared (dotta.store)   dotta's own — the marker its maker wrote — repaired
 *                            in place: a missing record, epoch or baseline is
 *                            re-made below and what stands is kept
 *   no references at all     a bare `git init`, taken. Untracked files are not
 *                            history and no step below touches them
 *   anything else            history dotta did not write; refused
 *
 * The repository this run just created is bare, undeclared and refless and passes
 * on the third row, so no flag is needed to keep a refusal from stranding it. A
 * bare repository a hand stripped of its HEAD arrives here whole again — the
 * open failed on the missing file and the init wrote it back — and is then judged
 * by its refs like any other: a foreign one is refused with a HEAD it did not
 * have, which git needs to open it at all.
 */
static error_t ensure_repository_adoptable(
    const dotta_ctx_t *ctx,
    git_repository *repo,
    const char *path
) {
    CHECK_NULL(ctx);
    CHECK_NULL(repo);
    CHECK_NULL(path);

    /* The declaration first, read off the repository's own config file, which
     * it refuses where libgit2 could not open it: libgit2 drops that level as
     * absent and core.bare goes with it (repository.c load_config_data reads an
     * unset value as not bare), so a bare store whose config will not open would
     * answer "a working tree" below */
    bool declared = false;
    error_t err = repo_is_store(repo, &declared);
    if (err) return err;

    /* The shape before the declaration is taken: a repository with a working
     * tree is refused whatever it declares */
    if (!git_repository_is_bare(repo)) {
        return error_create(
            ERR_CONFLICT, "'%s' is a Git repository with a working tree, and dotta's "
            "store is bare", path
        );
    }
    if (declared) return NULL;

    /* Any reference at all is history this run did not write, and the listing
     * that says there is none is complete or an error (sys/gitops.h): a `refs`
     * this run cannot read refuses here rather than being taken over.
     * `git_repository_is_empty` answers a narrower question — it also requires
     * HEAD to name the configured initial branch, so `git init --bare` followed
     * by `git symbolic-ref HEAD refs/heads/x` would fail it and be refused with
     * nothing to lose. */
    string_array_t refs;
    err = gitops_list_refs(repo, "refs", ctx->arena, &refs);
    if (err) {
        return error_wrap(err, "Failed to list repository references");
    }
    if (refs.count == 0) return NULL;

    return error_create(ERR_CONFLICT, "'%s' is a Git repository dotta did not create", path);
}

/**
 * Initialize state file
 *
 * Opens a write-locked handle, which creates dotta.db with the schema if it does
 * not already exist, then commits the empty transaction. A clean state file on
 * disk means subsequent commands do not have to bootstrap it.
 */
static error_t init_state(git_repository *repo) {
    CHECK_NULL(repo);

    state_t *state = NULL;
    error_t err = state_open(repo, &state);
    if (err) return err;

    err = state_save(state);
    state_free(state);

    if (err) return error_wrap(err, "Failed to save initial state");

    return NULL;
}

/**
 * Initialize command implementation
 */
error_t cmd_init(const dotta_ctx_t *ctx, const cmd_init_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->preset);   /* init_post_parse judged the strength */

    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    git_repository *repo = NULL;
    error_t err = NULL;
    const char *path = NULL;
    const char *elsewhere = NULL;

    /* Where the repository goes: the positional when one was given, this machine's
     * configured location otherwise — one answer, expanded, absolute and with
     * its parents made (utils/repo.h). */
    err = repo_create_target(config, ctx->arena, opts->repo_path, &path, &elsewhere);
    if (err) goto cleanup;

    /* The store: opened where a repository stands, made where nothing does. Only
     * an absence is created over, and the open proves one before it answers it
     * (sys/gitops.h gitops_open_repository): a repository that would not open —
     * a project's .git this run cannot read, a store whose HEAD stands over missing
     * objects, another user's, a config that will not parse — is not one to write
     * into, and its own refusal says why. A store a hand stripped of its HEAD
     * is the absence of the one file that makes a store, and is made whole by
     * the init, refs and all (gitops_init_repository). */
    err = gitops_open_repository(&repo, path);
    if (error_code(err) == ERR_NOT_FOUND) {
        err = gitops_init_repository(&repo, path);
    }
    if (err) {
        err = error_wrap(err, "Failed to initialize repository");
        goto cleanup;
    }

    /* Whose repository is this? Asked before the first step below writes, so a
     * refusal leaves it exactly as it was found. */
    err = ensure_repository_adoptable(ctx, repo, path);
    if (err) goto cleanup;

    /*
     * Idempotent setup. Each step is safe to re-run on an existing repository:
     * a fully-healthy repo no-ops at every step, and a partial prior init.
     */

    /* Declared dotta's: the marker repo_open reads, and the reflog a bare
     * repository does not keep by default (utils/repo.h). */
    err = repo_declare_store(repo);
    if (err) goto cleanup;

    /* state.db schema (state_open creates if missing) */
    err = init_state(repo);
    if (err) goto cleanup;

    /* The repository's epoch at refs/dotta/epoch, minted at the preset's strength.
     * Idempotent — keeps an existing valid one; one that yields no epoch is
     * regenerated when the ciphertext census proves the repository holds none,
     * and surfaced as an error otherwise. Done unconditionally (not gated on
     * encryption_enabled) so a later `dotta key set` finds the epoch ready, and
     * so `dotta clone` of this repo can fetch it regardless of the cloner's
     * config. */
    kdf_epoch_t epoch;
    bool epoch_repaired = false;
    err = epoch_init(
        repo, opts->preset->memory_mib, opts->preset->passes, &epoch, &epoch_repaired
    );
    if (err) {
        /* ERR_CRYPTO is the refusal to mint over reachable ciphertext. It already
         * names the state of the ref and the restore that repairs it, so a wrap
         * would only push both under a line that says less. */
        if (error_code(err) != ERR_CRYPTO) {
            err = error_wrap(err, "Failed to initialize repository epoch");
        }
        goto cleanup;
    }
    if (epoch_repaired) {
        output_info(
            out, OUTPUT_NORMAL,
            "Repaired an unreadable repository epoch"
        );
    }

    /* An epoch that already stood is the repository's, whatever this run was
     * told: a strength given by name that it does not match is refused — a change
     * of strength is a new epoch, never a note — and one that matches, or none
     * given, is the no-op it reads as. */
    if (opts->strength && (epoch.memory_mib != opts->preset->memory_mib ||
        epoch.passes != opts->preset->passes)) {
        err = error_create(
            ERR_CONFLICT,
            "The repository's epoch is already minted at %u MiB, %u passes; "
            "a change of strength is a new epoch: remove the encrypted files, "
            "delete '%s', and run init again",
            (unsigned) epoch.memory_mib, (unsigned) epoch.passes, EPOCH_REF
        );
        goto cleanup;
    }

    /* Baseline .dottaignore at its own ref. Seeded once: a ref that already stands
     * keeps whatever the user made of it. */
    err = ignore_seed_baseline(repo);
    if (err) {
        err = error_wrap(err, "Failed to seed baseline .dottaignore");
        goto cleanup;
    }

    /* Success */
    output_success(out, OUTPUT_NORMAL, "Initialized dotta repository in %s", path);
    output_gap(out, OUTPUT_NORMAL);

    /* A repository outside the configured location is one no later command will
     * find: every one of them resolves that location and stops there, so the
     * next `dotta status` would answer "No dotta repository found at" the
     * configured location, the repository this run just made standing elsewhere. */
    if (elsewhere) {
        output_warning(
            out, OUTPUT_NORMAL, "dotta looks for its repository at %s", elsewhere
        );
        output_hint(out, OUTPUT_NORMAL, "To use the one just created, either:");
        output_hintline(out, OUTPUT_NORMAL, "  export DOTTA_REPO_DIR=%s", path);
        output_hintline(
            out, OUTPUT_NORMAL, "  or set repo_dir under [core] in the config file"
        );
        output_gap(out, OUTPUT_NORMAL);
    }

    output_hintline(out, OUTPUT_NORMAL, "Next steps:");
    output_hintline(out, OUTPUT_NORMAL, "  Create profile: dotta add --profile global ~/.bashrc");
    output_hintline(out, OUTPUT_NORMAL, "  Apply profiles: dotta apply");

cleanup:
    if (repo) git_repository_free(repo);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The strength the line names, or the default's, judged against the presets
 * (crypto/kdf.h kdf_presets): a name no preset carries refuses the line before
 * anything is made.
 */
static error_t init_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_init_options_t *o = opts_v;

    const char *name = o->strength ? o->strength : KDF_PRESET_DEFAULT;
    for (size_t i = 0; i < KDF_PRESET_COUNT; i++) {
        if (strcmp(kdf_presets[i].name, name) == 0) {
            o->preset = &kdf_presets[i];
            return NULL;
        }
    }

    return error_create(
        ERR_INVALID_ARG, "Unknown strength '%s' (valid: fast, balanced, paranoid)", name
    );
}

/**
 * What can stand at the cursor: a preset's name after --strength; otherwise the
 * repository location, a directory, until one is given.
 */
static args_want_t init_complete(
    const void *ctx, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) ctx;
    const cmd_init_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_init_options_t, strength)) {
        for (size_t i = 0; i < KDF_PRESET_COUNT; i++) {
            fprintf(
                out, "%s\t%u MiB, %u passes\n", kdf_presets[i].name,
                (unsigned) kdf_presets[i].memory_mib,
                (unsigned) kdf_presets[i].passes
            );
        }
        return ARGS_WANT_NONE;
    }

    return o->repo_path == NULL ? ARGS_WANT_DIRS : ARGS_WANT_NONE;
}

static error_t init_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_init(ctx, (const cmd_init_options_t *) opts_v);
}

static const args_opt_t init_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "strength",        "<preset>",
        cmd_init_options_t,strength,
        "Argon2id strength: fast, balanced or paranoid"
    ),
    ARGS_FLAG_SET(
        "q quiet",
        cmd_init_options_t,verbosity, DOTTA_VERBOSITY_QUIET,
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
        "Create a bare Git repository wired for dotta profiles. The\n"
        "repository path defaults to $DOTTA_REPO_DIR, then the path\n"
        "configured in config.toml, then the per-user default directory.\n",
    .notes       =
        "Existing Directories:\n"
        "  The store is a bare Git repository. A directory holding one with a\n"
        "  working tree, one whose history dotta did not write, or one that\n"
        "  will not open, is refused.\n"
        "  An empty bare repository, or no repository at all, is initialized\n"
        "  in place; dotta's own is repaired in place, and a baseline\n"
        "  .dottaignore already at its ref is kept.\n"
        "\n"
        "Strength:\n"
        "  The repository's Argon2id strength — the memory and passes every\n"
        "  passphrase is derived under, on every machine — is minted once,\n"
        "  here, and travels with the repository. It cannot be changed in\n"
        "  place: a new strength is a new epoch, which means removing the\n"
        "  encrypted files, deleting refs/dotta/epoch, and running init again.\n"
        "  An existing epoch is kept; naming a strength it does not match is\n"
        "  refused.\n",
    .examples    =
        "  %s init                    # Default location\n"
        "  %s init ~/dotfiles         # Custom path\n"
        "  %s init --strength fast    # A cheaper derivation (tests, throwaway)\n"
        "  %s init --quiet            # No progress output\n",
    .epilogue    =
        "See also:\n"
        "  %s add <profile> <file>    # Create and populate a profile\n"
        "  %s apply                   # Deploy enabled profiles\n",
    .opts_size   = sizeof(cmd_init_options_t),
    .opts        = init_opts,
    .post_parse  = init_post_parse,
    .complete    = init_complete,
    .dispatch    = init_dispatch,
};
