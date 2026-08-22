/**
 * completion.c - Shell completion helper
 *
 * Hidden subcommand providing completion data for shell scripts. All functions
 * follow the silent failure model - errors result in no output rather than error
 * messages to stderr.
 *
 * Each mode reads one authority: the enabled set (state), the view (every
 * enabled profile at HEAD, precedence resolved), or Git (a branch's tree or
 * history). The shell composes them per command; nothing here guesses which
 * one a command wants.
 */

#include "cmds/completion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "sys/gitops.h"
#include "sys/upstream.h"

/* Constants */
#define COMPLETE_COMMIT_SHORT_OID_LEN 8
#define COMPLETE_COMMIT_DEFAULT_LIMIT 20
#define COMPLETE_COMMIT_MAX_LIMIT 100
#define COMPLETE_COMMIT_SUMMARY_MAX 60
#define COMPLETE_REFSPEC_FILES_MAX 2000

/**
 * Output profile names
 *
 * Three sets, selected by flag: with neither, the enabled set in precedence
 * order; `local` every local branch, the enabled ones marked; `remote` the
 * remote-tracking branches no local branch has been created from yet (what
 * `profile fetch` would download). The two flags compose; the sets are
 * disjoint by construction. Branch order is the ref iteration's; the shell
 * sorts its candidates.
 *
 * @param repo Repository (borrowed)
 * @param state Borrowed state handle
 * @param arena Borrowed scratch arena (the remote name is arena-owned)
 * @param local Include every local branch
 * @param remote Include remote-tracking branches without a local counterpart
 */
static void complete_profiles(
    git_repository *repo,
    const state_t *state,
    arena_t *arena,
    bool local,
    bool remote
) {
    if (!local && !remote) {
        const state_profile_entry_t *rows = NULL;
        size_t count = 0;
        error_t *err = state_peek_profiles(state, &rows, &count);
        if (err) {
            error_free(err);
            return;
        }
        for (size_t i = 0; i < count; i++) {
            printf("%s\tEnabled profile\n", rows[i].name);
        }
        return;
    }

    if (local) {
        string_array_t *branches = NULL;
        error_t *err = profile_list_all_local(repo, &branches);
        if (err) {
            error_free(err);
        } else {
            for (size_t i = 0; i < branches->count; i++) {
                const char *branch = branches->items[i];
                printf(
                    "%s\t%s\n", branch,
                    state_has_profile(state, branch) ? "Enabled profile"
                                                     : "Available profile"
                );
            }
            string_array_free(branches);
        }
    }

    if (remote) {
        const char *remote_name = NULL;
        if (gitops_resolve_default_remote(repo, arena, &remote_name, NULL) != NULL) {
            return;  /* no remote configured: nothing to download */
        }
        string_array_t *branches = NULL;
        if (upstream_discover_branches(repo, remote_name, &branches) != NULL) {
            return;
        }
        for (size_t i = 0; i < branches->count; i++) {
            printf("%s\tRemote profile\n", branches->items[i]);
        }
        string_array_free(branches);
    }
}

/**
 * Output configured git remotes
 */
static void complete_remotes(git_repository *repo) {
    git_strarray remotes = { 0 };
    int git_err = git_remote_list(&remotes, repo);
    if (git_err == 0) {
        for (size_t i = 0; i < remotes.count; i++) {
            const char *name = remotes.strings[i];
            char *url = NULL;
            error_t *url_err = gitops_get_remote_url(repo, name, &url);
            printf(
                "%s\t%s\n",
                name, url ? url : "Remote"
            );
            free(url);
            error_free(url_err);
        }
        git_strarray_dispose(&remotes);
    }
}

/**
 * Output managed files: the view over the enabled set
 *
 * One row per managed path, the winning profile beside it. A profile filter
 * keeps the rows those profiles win — exactly the rows a workspace verb with
 * that filter acts on; a path a filtered profile holds but does not win is not
 * offered because the verb would skip it. Rows come in the view's order; the
 * shell sorts its candidates.
 *
 * @param repo Repository (borrowed)
 * @param state Borrowed state handle
 * @param mounts Per-machine mount table over the enabled set
 * @param arena Borrowed scratch arena (caller's command arena)
 * @param profiles Optional winner filter (NULL/0 for every row)
 * @param profile_count Number of names in the filter
 */
static void complete_files(
    git_repository *repo,
    const state_t *state,
    const mount_table_t *mounts,
    arena_t *arena,
    char *const *profiles,
    size_t profile_count
) {
    manifest_t *manifest = NULL;
    error_t *err = manifest_build(repo, state, mounts, arena, &manifest);
    if (err) {
        error_free(err);
        return;
    }

    manifest_rows_t rows = manifest_rows(manifest);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

        /* Files only: a directory row is a metadata claim, not a path the
         * file-taking verbs complete to */
        if (row->type == PATH_TYPE_DIRECTORY) {
            continue;
        }
        /* Winner filter, applied here rather than at the build: one view, one
         * loop. */
        if (profile_count > 0) {
            bool wanted = false;
            for (size_t j = 0; j < profile_count && !wanted; j++) {
                wanted = strcmp(row->profile, profiles[j]) == 0;
            }
            if (!wanted) continue;
        }
        printf("%s\t%s\n", row->storage_path, row->profile);
    }

    manifest_free(manifest);
}

/* Tree-walk state for complete_refspecs. */
typedef struct {
    const char *branch;   /* current branch (source of the "<branch>:" prefix) */
    bool prefix;          /* prefix "<branch>:" (all branches) vs bare path (pinned by -p) */
    size_t cap;
    size_t emitted;
    bool truncated;
} refspec_walk_ctx_t;

/**
 * Tree-walk callback: emit one token per managed file blob.
 *
 * `root` is "" at the top level or "dir/.../" with a trailing slash, so
 * mount_spec_for_path(root) gates emission to files under a storage label, skipping
 * top-level blobs, .dotta/, and any non-label root.
 */
static int refspec_emit_cb(
    const char *root,
    const git_tree_entry *entry,
    void *payload
) {
    refspec_walk_ctx_t *ctx = payload;

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) return 0;  /* descend trees */
    if (!mount_spec_for_path(root)) return 0;                     /* storage-label gate */

    const char *name = git_tree_entry_name(entry);
    if (ctx->prefix) {
        printf("%s:%s%s\n", ctx->branch, root, name);
    } else {
        printf("%s%s\t%s\n", root, name, ctx->branch);
    }

    if (++ctx->emitted >= ctx->cap) {
        ctx->truncated = true;
        return -1;  /* abort: wrapped as a git error, marked benign via ctx */
    }
    return 0;
}

/**
 * Output a branch's files as completion tokens, sourced from Git (not the
 * view) so the verbs that name a profile — remove, list, show, revert, export
 * — reach every file the branch holds: shadowed by a higher profile, or in a
 * profile disabled or never enabled here.
 *
 * @param repo Repository (borrowed)
 * @param profile NULL: every local branch, emit "<profile>:<path>". Else: that
 *                branch only, emit bare "<path>" (the profile is pinned).
 * @param cap Backstop on total tokens emitted
 */
static void complete_refspecs(
    git_repository *repo,
    const char *profile,
    size_t cap
) {
    string_array_t *branches = NULL;
    if (profile) {
        branches = string_array_new(1);
        if (!branches) return;
        error_t *err = string_array_push(branches, profile);
        if (err) {
            error_free(err);
            string_array_free(branches);
            return;
        }
    } else {
        error_t *err = profile_list_all_local(repo, &branches);
        if (err) {
            error_free(err);  /* silent-failure model */
            return;
        }
        string_array_sort(branches);  /* deterministic order under the cap */
    }

    refspec_walk_ctx_t ctx = { .cap = cap, .prefix = (profile == NULL) };
    for (size_t i = 0; i < branches->count; i++) {
        const char *branch = branches->items[i];

        git_tree *tree = NULL;
        error_t *load_err = gitops_load_branch_tree(repo, branch, &tree, NULL);
        if (load_err) {
            error_free(load_err);  /* not a branch, or unloadable: silent */
            continue;
        }

        ctx.branch = branch;
        error_t *walk_err = gitops_tree_walk(tree, refspec_emit_cb, &ctx);
        git_tree_free(tree);
        if (walk_err) error_free(walk_err);  /* benign on cap-abort; else also silent */
        if (ctx.truncated) break;            /* cap hit (the walk error above was the abort) */
    }

    string_array_free(branches);
}

/**
 * Output recent commits for completion
 *
 * Walks each branch's history from its tip, newest first, up to `limit` per
 * branch. The branches are the ones named, else the enabled set in precedence
 * order — the set show and diff resolve a bare reference against, in that
 * order. When more than one history is listed, the description carries the
 * branch so the interleaved hashes stay attributable.
 *
 * Output: <short_oid>\t<summary>, or <short_oid>\t<branch>: <summary>.
 *
 * @param repo Repository (borrowed)
 * @param state Borrowed state handle (read only when no branch is named)
 * @param profiles Branches to walk (NULL/0 for the enabled set)
 * @param profile_count Number of branches named
 * @param limit Maximum number of commits per branch
 */
static void complete_commits(
    git_repository *repo,
    const state_t *state,
    char *const *profiles,
    size_t profile_count,
    long limit
) {
    string_array_t *branches STRING_ARRAY_CLEANUP = string_array_new(profile_count);
    if (!branches) return;

    error_t *err = NULL;
    if (profile_count > 0) {
        for (size_t i = 0; i < profile_count && !err; i++) {
            err = string_array_push(branches, profiles[i]);
        }
    } else {
        const state_profile_entry_t *rows = NULL;
        size_t count = 0;
        err = state_peek_profiles(state, &rows, &count);
        for (size_t i = 0; i < count && !err; i++) {
            err = string_array_push(branches, rows[i].name);
        }
    }
    if (err) {
        error_free(err);
        return;
    }

    bool label = branches->count > 1;

    for (size_t b = 0; b < branches->count; b++) {
        const char *branch = branches->items[b];

        /* Resolve reference using DWIM (handles branches, tags, remotes) */
        git_reference *ref = NULL;
        if (git_reference_dwim(&ref, repo, branch) != 0) {
            continue;  /* not a branch: nothing from it */
        }

        /* Peel to commit (handles symbolic refs and tags automatically) */
        git_object *obj = NULL;
        int git_err = git_reference_peel(&obj, ref, GIT_OBJECT_COMMIT);
        git_reference_free(ref);
        if (git_err != 0) {
            continue;
        }

        git_revwalk *walker = NULL;
        if (git_revwalk_new(&walker, repo) != 0) {
            git_object_free(obj);
            continue;
        }
        git_revwalk_push(walker, git_object_id(obj));
        git_revwalk_sorting(walker, GIT_SORT_TIME);

        git_oid oid;
        long count = 0;
        while (count < limit && git_revwalk_next(&oid, walker) == 0) {
            git_commit *commit = NULL;
            if (git_commit_lookup(&commit, repo, &oid) != 0) {
                continue;
            }

            const char *message = git_commit_message(commit);
            if (!message) {
                git_commit_free(commit);
                continue;
            }

            /* Format short OID */
            char oid_str[COMPLETE_COMMIT_SHORT_OID_LEN + 1];
            git_oid_tostr(oid_str, sizeof(oid_str), &oid);

            /* Extract first line of commit message */
            const char *newline = strchr(message, '\n');
            size_t msg_len =
                newline ? (size_t) (newline - message) : strlen(message);
            if (msg_len > COMPLETE_COMMIT_SUMMARY_MAX) {
                msg_len = COMPLETE_COMMIT_SUMMARY_MAX;
            }

            if (label) {
                printf("%s\t%s: %.*s\n", oid_str, branch, (int) msg_len, message);
            } else {
                printf("%s\t%.*s\n", oid_str, (int) msg_len, message);
            }

            git_commit_free(commit);
            count++;
        }

        git_revwalk_free(walker);
        git_object_free(obj);
    }
}

/**
 * Run completion command
 *
 * Dispatches to appropriate completion function based on mode. Always returns
 * NULL (success) - errors result in no output.
 */
error_t *cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts) {
    if (!ctx || !opts) {
        return NULL;  /* Silent failure */
    }

    if (opts->mode == COMPLETE_SPEC_FISH) {
        /* Build-time emission: projects the root registry into the
         * fish-completion dialect. Stable, repo-independent, invoked by `make
         * completions` to generate the schema under build/. Registry is
         * borrowed from main.c via the typed accessor so the cmds/ layer
         * never names the registry symbol. */
        args_export_completion_fish(stdout, ctx->arena, dotta_registry(), "dotta");
        return NULL;
    }

    /* OPTIONAL_SILENT + READ: outside a repository the dispatcher hands over
     * neither repo nor state; every data mode answers with silence. Inside
     * one, state and mounts follow the repo (the runtime invariants). */
    git_repository *repo = ctx->repo;
    if (!repo) {
        return NULL;
    }

    switch (opts->mode) {
        case COMPLETE_PROFILES:
            complete_profiles(repo, ctx->state, ctx->arena, opts->local, opts->remote);
            break;

        case COMPLETE_FILES:
            complete_files(
                repo, ctx->state, ctx->mounts, ctx->arena,
                opts->profiles, opts->profile_count
            );
            break;

        case COMPLETE_REFSPECS:
            /* post_parse admits at most one -p here */
            complete_refspecs(
                repo, opts->profile_count > 0 ? opts->profiles[0] : NULL,
                COMPLETE_REFSPEC_FILES_MAX
            );
            break;

        case COMPLETE_COMMITS:
            complete_commits(
                repo, ctx->state, opts->profiles, opts->profile_count, opts->limit
            );
            break;

        case COMPLETE_REMOTES:
            complete_remotes(repo);
            break;

        case COMPLETE_SPEC_FISH:
            break;  /* handled above */
    }

    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Seed the default: commits mode returns up to 20 rows per branch when
 * `--limit` isn't supplied.
 */
static void completion_init_defaults(void *opts_v) {
    cmd_completion_options_t *o = opts_v;
    o->limit = COMPLETE_COMMIT_DEFAULT_LIMIT;
}

/**
 * Map the mandatory first positional into `mode`.
 *
 * Silent-failure semantics (suppressed by the dispatcher when `silent_failure =
 * true`): a missing or unknown mode returns exit 1 with no stderr output — this
 * preserves shell-completion contract with fish scripts that invoke `dotta
 * __complete ...`.
 *
 * `spec` mode takes a second positional naming the output dialect (currently
 * only `fish`). All other modes require exactly one positional — we reject extras
 * explicitly so a typo like `dotta __complete profiles all` doesn't silently
 * ignore `all`. Likewise each flag is admitted only by the modes that read it:
 * `--local` / `--remote` by profiles, `-p` by files, refspecs (one) and commits.
 */
static error_t *completion_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_completion_options_t *o = opts_v;

    if (o->positional_count == 0) {
        return error_create(ERR_INVALID_ARG, "completion mode is required");
    }

    const char *mode = o->positional_args[0];

    if (strcmp(mode, "profiles") == 0) {
        o->mode = COMPLETE_PROFILES;
    } else if (strcmp(mode, "files") == 0) {
        o->mode = COMPLETE_FILES;
    } else if (strcmp(mode, "refspecs") == 0) {
        o->mode = COMPLETE_REFSPECS;
    } else if (strcmp(mode, "commits") == 0) {
        o->mode = COMPLETE_COMMITS;
    } else if (strcmp(mode, "remotes") == 0) {
        o->mode = COMPLETE_REMOTES;
    } else if (strcmp(mode, "spec") == 0) {
        if (o->positional_count < 2) {
            return error_create(
                ERR_INVALID_ARG,
                "'spec' mode requires a dialect (e.g. 'fish')"
            );
        }
        const char *dialect = o->positional_args[1];
        if (strcmp(dialect, "fish") != 0) {
            return error_create(
                ERR_INVALID_ARG, "unknown spec dialect '%s'", dialect
            );
        }
        o->mode = COMPLETE_SPEC_FISH;
    } else {
        return error_create(ERR_INVALID_ARG, "unknown completion mode '%s'", mode);
    }

    /* Non-spec modes take exactly one positional. */
    if (o->mode != COMPLETE_SPEC_FISH && o->positional_count > 1) {
        return error_create(
            ERR_INVALID_ARG,
            "'%s' mode takes no additional positional arguments", mode
        );
    }

    /* Each flag belongs to the modes that read it. */
    if ((o->local || o->remote) && o->mode != COMPLETE_PROFILES) {
        return error_create(
            ERR_INVALID_ARG, "--local and --remote are only valid with 'profiles' mode"
        );
    }
    bool takes_profiles = o->mode == COMPLETE_FILES ||
        o->mode == COMPLETE_REFSPECS ||
        o->mode == COMPLETE_COMMITS;
    if (o->profile_count > 0 && !takes_profiles) {
        return error_create(
            ERR_INVALID_ARG, "-p is only valid with 'files', 'refspecs' or 'commits' mode"
        );
    }
    if (o->mode == COMPLETE_REFSPECS && o->profile_count > 1) {
        return error_create(
            ERR_INVALID_ARG, "'refspecs' mode pins at most one profile"
        );
    }
    return NULL;
}

static error_t *completion_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_completion(ctx, (const cmd_completion_options_t *) opts_v);
}

static const args_opt_t completion_opts[] = {
    ARGS_FLAG(
        "local",
        cmd_completion_options_t,local,
        "Profiles: every local branch, the enabled ones marked"
    ),
    ARGS_FLAG(
        "remote",
        cmd_completion_options_t,remote,
        "Profiles: remote-tracking branches without a local branch"
    ),
    ARGS_APPEND(
        "p profile",             "<name>",
        cmd_completion_options_t,profiles,        profile_count,
        "Files: rows this profile wins; commits: this branch; refspecs: pin it"
    ),
    ARGS_INT(
        "l limit",               "<N>",
        cmd_completion_options_t,limit,           1,                COMPLETE_COMMIT_MAX_LIMIT,
        "Commits: maximum per branch (default: 20)"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_completion_options_t,positional_args, positional_count,
        1,                       2
    ),
    ARGS_END,
};

const args_command_t spec_completion = {
    .name           = "__complete",
    .summary        = "Shell completion helper (hidden)",
    .usage          = "%s __complete <mode> [<arg>] [options]",
    .opts_size      = sizeof(cmd_completion_options_t),
    .opts           = completion_opts,
    .init_defaults  = completion_init_defaults,
    .post_parse     = completion_post_parse,
    .payload        = &dotta_ext_read_silent,
    .dispatch       = completion_dispatch,
    .silent_failure = true,
    .hidden         = true,
};
