/**
 * completion.c - Shell completion helper
 *
 * Hidden subcommand providing completion data for shell scripts.
 * All functions follow the silent failure model - errors result in
 * no output rather than error messages to stderr.
 */

#include "cmds/completion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "core/state.h"
#include "sys/gitops.h"
#include "sys/upstream.h"

/* Constants */
#define COMPLETE_COMMIT_SHORT_OID_LEN 8
#define COMPLETE_COMMIT_DEFAULT_LIMIT 20
#define COMPLETE_COMMIT_MAX_LIMIT 100
#define COMPLETE_COMMIT_SUMMARY_MAX 60

/**
 * Output enabled profiles from state database
 *
 * Queries the enabled_profiles table and outputs profile names.
 *
 * @param state Borrowed state handle; NULL when running outside a repo
 */
static void complete_enabled_profiles(state_t *state) {
    if (!state) return;

    string_array_t *profiles = NULL;
    error_t *err = state_get_profiles(state, &profiles);
    if (err) {
        error_free(err);
        return;
    }

    /* Sort enabled profiles alphabetically for easier completion */
    string_array_sort(profiles);

    for (size_t i = 0; i < profiles->count; i++) {
        printf(
            "%s\tEnabled Profile\n",
            profiles->items[i]
        );
    }

    string_array_free(profiles);
}

/**
 * Output all available profiles
 *
 * Lists all local branches and remote-tracking branches,
 * excluding the internal dotta-worktree branch.
 */
static void complete_all_profiles(git_repository *repo) {
    /* 1. Local branches */
    string_array_t *branches = NULL;
    error_t *err = gitops_list_branches(repo, &branches);
    if (!err) {
        string_array_sort(branches);
        for (size_t i = 0; i < branches->count; i++) {
            const char *profile = branches->items[i];
            /* Skip internal worktree branch */
            if (strcmp(profile, "dotta-worktree") != 0) {
                printf("%s\tProfile\n", profile);
            }
        }
    } else {
        error_free(err);
    }

    /* 2. Remote tracking branches */
    char *remote_name = NULL;
    if (upstream_detect_remote(repo, &remote_name) == NULL) {
        string_array_t *remote_branches = NULL;
        if (upstream_discover_branches(repo, remote_name, &remote_branches) == NULL) {
            string_array_sort(remote_branches);
            for (size_t i = 0; i < remote_branches->count; i++) {
                printf(
                    "%s\tRemote Profile\n",
                    remote_branches->items[i]
                );
            }
            string_array_free(remote_branches);
        }
        free(remote_name);
    }

    if (branches) {
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
 * Output managed files from state database
 *
 * @param state Borrowed state handle; NULL when running outside a repo
 * @param profile Optional profile filter (NULL for all files)
 * @param storage_paths If true, output storage_path; if false, filesystem_path
 */
static void complete_files(
    state_t *state,
    const char *profile,
    bool storage_paths
) {
    if (!state) return;

    arena_t *arena = arena_create(0);
    if (!arena) return;

    state_file_entry_t *entries = NULL;
    size_t count = 0;
    error_t *err = NULL;

    if (profile) {
        err = state_get_entries_by_profile(
            state, profile, arena, &entries, &count
        );
    } else {
        err = state_get_all_files(
            state, arena, &entries, &count
        );
    }

    if (err) {
        error_free(err);
        arena_destroy(arena);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        /* Skip entries staged for removal */
        if (entries[i].state &&
            (strcmp(entries[i].state, STATE_DELETED) == 0 ||
            strcmp(entries[i].state, STATE_RELEASED) == 0)) {
            continue;
        }
        const char *path = storage_paths ? entries[i].storage_path
                                         : entries[i].filesystem_path;
        if (path) {
            printf(
                "%s\t%s\n",
                path, entries[i].profile
            );
        }
    }

    arena_destroy(arena);
}

/**
 * Output recent commits for completion
 *
 * Outputs commits in tab-separated format: <short_oid>\t<summary>
 * This allows fish to display the summary as a description.
 *
 * @param repo Repository (borrowed)
 * @param state Borrowed state handle; NULL when running outside a repo
 * @param profile Profile to get commits from (NULL uses first enabled profile)
 * @param limit Maximum number of commits to output
 */
static void complete_commits(
    git_repository *repo,
    state_t *state,
    const char *profile,
    long limit
) {
    /* Clamp limit to reasonable bounds */
    if (limit <= 0) {
        limit = COMPLETE_COMMIT_DEFAULT_LIMIT;
    }
    if (limit > COMPLETE_COMMIT_MAX_LIMIT) {
        limit = COMPLETE_COMMIT_MAX_LIMIT;
    }

    /* Determine target profile */
    const char *target_profile = profile;
    string_array_t *profiles STRING_ARRAY_CLEANUP = NULL;

    /* If no profile specified, use first enabled profile from state */
    if (!profile) {
        if (!state) return;

        error_t *err = state_get_profiles(state, &profiles);
        if (err) {
            error_free(err);
            return;
        }

        if (profiles->count > 0) {
            target_profile = profiles->items[0];
        }
    }

    if (!target_profile) return;

    /* Resolve reference using DWIM (handles branches, tags, remotes) */
    git_reference *ref = NULL;
    int git_err = git_reference_dwim(&ref, repo, target_profile);
    if (git_err != 0) {
        return;
    }

    /* Peel to commit (handles symbolic refs and tags automatically) */
    git_object *obj = NULL;
    git_err = git_reference_peel(&obj, ref, GIT_OBJECT_COMMIT);
    git_reference_free(ref);
    if (git_err != 0) {
        return;
    }

    const git_oid *head_oid = git_object_id(obj);

    /* Create revision walker */
    git_revwalk *walker = NULL;
    git_err = git_revwalk_new(&walker, repo);
    if (git_err != 0) {
        git_object_free(obj);
        return;
    }

    git_revwalk_push(walker, head_oid);
    git_revwalk_sorting(walker, GIT_SORT_TIME);

    /* Walk commits and output */
    git_oid oid;
    long count = 0;
    while (git_revwalk_next(&oid, walker) == 0 && count < limit) {
        git_commit *commit = NULL;
        if (git_commit_lookup(&commit, repo, &oid) != 0) {
            continue;
        }

        /* Format short OID */
        char oid_str[COMPLETE_COMMIT_SHORT_OID_LEN + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &oid);

        /* Extract first line of commit message */
        const char *message = git_commit_message(commit);
        if (!message) {
            git_commit_free(commit);
            continue;
        }
        const char *newline = strchr(message, '\n');
        size_t msg_len =
            newline ? (size_t) (newline - message) : strlen(message);

        if (msg_len > COMPLETE_COMMIT_SUMMARY_MAX) {
            msg_len = COMPLETE_COMMIT_SUMMARY_MAX;
        }

        /* Output: <oid>\t<summary> */
        printf("%s\t%.*s\n", oid_str, (int) msg_len, message);

        git_commit_free(commit);
        count++;
    }

    git_revwalk_free(walker);
    git_object_free(obj);
}

/**
 * Run completion command
 *
 * Dispatches to appropriate completion function based on mode.
 * Always returns NULL (success) - errors result in no output.
 */
error_t *cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts) {
    if (!ctx || !opts) {
        return NULL;  /* Silent failure */
    }

    git_repository *repo = ctx->repo;
    /* OPTIONAL_SILENT + READ: the dispatcher skips state acquisition when
     * no repo is available, so state may legitimately be NULL here */
    state_t *state = ctx->state;

    switch (opts->mode) {
        case COMPLETE_CHECK:
            /* The dispatcher opens the repo in OPTIONAL_SILENT mode.
             * Repo presence is the signal; silent_failure turns a
             * missing repo into exit 1 with no output. */
            if (!repo) {
                return error_create(
                    ERR_NOT_FOUND, "not in a dotta repository"
                );
            }
            break;

        case COMPLETE_PROFILES:
            if (!repo) {
                return NULL;
            }
            if (opts->all) {
                complete_all_profiles(repo);
            } else {
                complete_enabled_profiles(state);
            }
            break;

        case COMPLETE_FILES:
            if (!repo) {
                return NULL;
            }
            complete_files(state, opts->profile, opts->storage_paths);
            break;

        case COMPLETE_COMMITS:
            if (!repo) {
                return NULL;
            }
            complete_commits(repo, state, opts->profile, opts->limit);
            break;

        case COMPLETE_REMOTES:
            if (!repo) {
                return NULL;
            }
            complete_remotes(repo);
            break;

        case COMPLETE_SPEC_FISH:
            /* Build-time emission: projects the root registry into the
             * fish-completion dialect. Stable, repo-independent, invoked
             * by `make completions` to generate the schema under build/.
             * Registry is borrowed from main.c via the typed accessor
             * so the cmds/ layer never names the registry symbol. */
            args_export_completion_fish(stdout, dotta_registry(), "dotta");
            break;

        default:
            /* Unknown mode - silent failure */
            break;
    }

    return NULL;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Seed the legacy default: commits mode returns up to 20 rows when
 * `--limit` isn't supplied.
 */
static void completion_init_defaults(void *opts_v) {
    cmd_completion_options_t *o = opts_v;
    o->limit = COMPLETE_COMMIT_DEFAULT_LIMIT;
}

/**
 * Map the mandatory first positional into `mode`.
 *
 * Silent-failure semantics (suppressed by the dispatcher when
 * `silent_failure = true`): a missing or unknown mode returns exit 1
 * with no stderr output — this preserves shell-completion contract
 * with fish scripts that invoke `dotta __complete ...`.
 *
 * `spec` mode takes a second positional naming the output dialect
 * (currently only `fish`). All other modes require exactly one
 * positional — we reject extras explicitly so a typo like
 * `dotta __complete profiles all` doesn't silently ignore `all`.
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
    if (strcmp(mode, "check") == 0) {
        o->mode = COMPLETE_CHECK;
    } else if (strcmp(mode, "profiles") == 0) {
        o->mode = COMPLETE_PROFILES;
    } else if (strcmp(mode, "files") == 0) {
        o->mode = COMPLETE_FILES;
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
        if (strcmp(dialect, "fish") == 0) {
            o->mode = COMPLETE_SPEC_FISH;
        } else {
            return error_create(
                ERR_INVALID_ARG, "unknown spec dialect '%s'", dialect
            );
        }
        return NULL;
    } else {
        return error_create(ERR_INVALID_ARG, "unknown completion mode '%s'", mode);
    }

    /* Non-spec modes take exactly one positional. */
    if (o->positional_count > 1) {
        return error_create(
            ERR_INVALID_ARG,
            "'%s' mode takes no additional positional arguments", mode
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
        "a all",
        cmd_completion_options_t,all,
        "Include all available profiles (not just enabled)"
    ),
    ARGS_FLAG(
        "s storage",
        cmd_completion_options_t,storage_paths,
        "Output storage paths instead of filesystem paths"
    ),
    ARGS_STRING(
        "p profile",             "<name>",
        cmd_completion_options_t,profile,
        "Filter by profile"
    ),
    ARGS_INT(
        "l limit",               "<N>",
        cmd_completion_options_t,limit,           1,                 1000,
        "Maximum number of commits to list (default: 20)"
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
