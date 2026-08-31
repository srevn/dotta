/**
 * completion.c - Shell completion: the script, the candidates and their sources
 *
 * `dotta __complete` answers the shell's question — what can stand at the cursor
 * of a command line — through the spec engine: the line is consumed as the parser
 * would consume it, and the command's `complete` hook prints what its grammar
 * admits at that position. The sources the hooks draw on live here, one authority
 * each: the enabled set (state), the view (every enabled profile at HEAD,
 * precedence resolved), or Git (a branch's tree or history). The hooks compose
 * them per command; nothing here guesses which one a command wants. `dotta
 * completion <shell>` prints the script that asks.
 *
 * The sources fail silently: errors result in no output rather than messages to
 * stderr, and outside a repository every source prints nothing.
 */

#include "cmds/completion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/refspec.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/metadata.h"
#include "core/profiles.h"
#include "core/state.h"
#include "infra/mount.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/upstream.h"

/* Emission limits */
#define COMPLETE_COMMIT_SHORT_OID_LEN 8
#define COMPLETE_COMMIT_LIMIT 20
#define COMPLETE_COMMIT_SUMMARY_MAX 60
#define COMPLETE_REFSPEC_FILES_MAX 2000

/**
 * Profile names, by the set the slot admits
 */
void completion_profiles(
    const dotta_ctx_t *ctx, FILE *out, completion_profiles_t set
) {
    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    if (repo == NULL) return;

    if (set == COMPLETION_ENABLED) {
        const state_profile_entry_t *rows = NULL;
        size_t count = 0;
        error_t *err = state_peek_profiles(state, &rows, &count);
        if (err) {
            error_free(err);
            return;
        }
        for (size_t i = 0; i < count; i++) {
            fprintf(out, "%s\tEnabled profile\n", rows[i].name);
        }
        return;
    }

    string_array_t *branches = NULL;
    error_t *err = profile_list_all_local(repo, &branches);
    if (err) {
        error_free(err);
    } else {
        for (size_t i = 0; i < branches->count; i++) {
            const char *branch = branches->items[i];
            fprintf(
                out, "%s\t%s\n", branch,
                state_has_profile(state, branch) ? "Enabled profile"
                                                 : "Available profile"
            );
        }

        string_array_free(branches);
    }

    if (set == COMPLETION_ALL) {
        const char *remote_name = NULL;
        err = gitops_resolve_default_remote(repo, ctx->arena, &remote_name, NULL);
        if (err) {
            error_free(err);  /* no remote configured: nothing to download */
            return;
        }
        string_array_t *remote_branches = NULL;
        err = upstream_discover_branches(repo, remote_name, &remote_branches);
        if (err) {
            error_free(err);
            return;
        }
        for (size_t i = 0; i < remote_branches->count; i++) {
            fprintf(out, "%s\tRemote profile\n", remote_branches->items[i]);
        }

        string_array_free(remote_branches);
    }
}

/**
 * Configured git remotes, the URL as description
 */
void completion_remotes(const dotta_ctx_t *ctx, FILE *out) {
    git_repository *repo = ctx->run.repo;
    if (repo == NULL) return;

    git_strarray remotes = { 0 };
    if (git_remote_list(&remotes, repo) != 0) return;

    for (size_t i = 0; i < remotes.count; i++) {
        const char *name = remotes.strings[i];
        char *url = NULL;
        error_t *url_err = gitops_get_remote_url(repo, name, &url);
        fprintf(out, "%s\t%s\n", name, url ? url : "Remote");
        free(url);
        error_free(url_err);
    }

    git_strarray_dispose(&remotes);
}

/**
 * The view's files, narrowed to the winners named — and, when asked, its directory
 * claims, slash-marked
 */
void completion_files(
    const dotta_ctx_t *ctx, FILE *out,
    char *const *winners, size_t winner_count, bool directories
) {
    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    if (repo == NULL) return;

    /* The full view per request is priced and fine: ~10 ms end-to-end for the
     * whole `dotta __complete` invocation (process start included) on a 4-profile
     * / ~180-row repository, measured 2026-08 — well inside a tab-press. */
    manifest_t *manifest = NULL;
    error_t *err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) {
        error_free(err);
        return;
    }

    manifest_rows_t rows = manifest_rows(manifest);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

        if (row->type == PATH_TYPE_DIRECTORY && !directories) {
            continue;
        }
        /* Winner filter, applied here rather than at the build: one view, one
         * loop. */
        if (winner_count > 0) {
            bool wanted = false;
            for (size_t j = 0; j < winner_count && !wanted; j++) {
                wanted = strcmp(row->profile, winners[j]) == 0;
            }
            if (!wanted) continue;
        }
        fprintf(
            out, "%s%s\t%s\n", row->storage_path,
            path_kind_suffix(path_type_kind(row->type)), row->profile
        );
    }

    manifest_free(manifest);
}

/**
 * A branch's directory claims, read from its metadata rather than the view
 */
void completion_directories(
    const dotta_ctx_t *ctx, FILE *out, const char *branch
) {
    git_repository *repo = ctx->run.repo;
    if (repo == NULL || branch == NULL) return;

    metadata_t *metadata = NULL;
    error_t *err = metadata_load_from_branch(repo, branch, &metadata);
    if (err) {
        error_free(err);  /* not a branch, or no metadata: nothing to offer */
        return;
    }

    size_t count = 0;
    const metadata_item_t *const *items = metadata_items(metadata, &count);
    for (size_t i = 0; i < count; i++) {
        if (items[i]->kind != PATH_KIND_DIRECTORY) continue;
        fprintf(out, "%s/\t%s\n", items[i]->key, branch);
    }

    metadata_free(metadata);
}

/* Tree-walk state for completion_refspecs. */
typedef struct {
    FILE *out;
    const char *branch;   /* current branch (source of the "<branch>:" prefix) */
    bool prefix;          /* prefix "<branch>:" (all branches) vs bare path (pinned) */
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
    const char *root, const git_tree_entry *entry, void *payload
) {
    refspec_walk_ctx_t *walk = payload;

    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) return 0;  /* descend trees */
    if (!mount_spec_for_path(root)) return 0;                     /* storage-label gate */

    const char *name = git_tree_entry_name(entry);
    if (walk->prefix) {
        fprintf(
            walk->out, "%s:%s%s\n", walk->branch, root, name
        );
    } else {
        fprintf(
            walk->out, "%s%s\t%s\n", root, name, walk->branch
        );
    }

    if (++walk->emitted >= walk->cap) {
        walk->truncated = true;
        return -1;  /* abort: wrapped as a git error, marked benign via walk */
    }
    return 0;
}

/**
 * A branch's files, read from Git rather than the view
 */
void completion_refspecs(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
) {
    git_repository *repo = ctx->run.repo;
    if (repo == NULL) return;

    string_array_t *branches = NULL;
    if (pinned) {
        branches = string_array_new(1);
        if (!branches) return;
        error_t *err = string_array_push(branches, pinned);
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

    refspec_walk_ctx_t walk = {
        .out    = out,
        .cap    = COMPLETE_REFSPEC_FILES_MAX,
        .prefix = (pinned == NULL)
    };

    for (size_t i = 0; i < branches->count; i++) {
        const char *branch = branches->items[i];

        git_tree *tree = NULL;
        error_t *load_err = gitops_load_branch_tree(repo, branch, &tree, NULL);
        if (load_err) {
            error_free(load_err);  /* not a branch, or unloadable: silent */
            continue;
        }

        walk.branch = branch;
        error_t *walk_err = gitops_tree_walk(tree, refspec_emit_cb, &walk);
        git_tree_free(tree);
        if (walk_err) error_free(walk_err);  /* benign on cap-abort; else also silent */
        if (walk.truncated) break;           /* cap hit (the walk error above was the abort) */
    }

    string_array_free(branches);
}

/**
 * Walk each branch's history from its tip, newest first, up to the per-branch
 * limit; a name that resolves to no branch contributes nothing. When more than
 * one history is listed, the description carries the branch so the interleaved
 * hashes stay attributable. `prefix`, when given, is printed before every token
 * as `<prefix>@<token>`.
 *
 * @return Number of commits emitted
 */
static size_t commits_walk(
    git_repository *repo, FILE *out, const char *prefix,
    const char *const *branches, size_t branch_count
) {
    bool label = branch_count > 1;
    size_t emitted = 0;

    for (size_t b = 0; b < branch_count; b++) {
        const char *branch = branches[b];

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
        while (count < COMPLETE_COMMIT_LIMIT && git_revwalk_next(&oid, walker) == 0) {
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

            if (prefix) fprintf(out, "%s@", prefix);
            if (label) {
                fprintf(out, "%s\t%s: %.*s\n", oid_str, branch, (int) msg_len, message);
            } else {
                fprintf(out, "%s\t%.*s\n", oid_str, (int) msg_len, message);
            }

            git_commit_free(commit);
            count++;
            emitted++;
        }

        git_revwalk_free(walker);
        git_object_free(obj);
    }

    return emitted;
}

/**
 * The commit candidates, with or without a `<prefix>@` in front of each: the
 * reference forms first, then the named histories, else the enabled ones.
 */
static void commits_emit(
    const dotta_ctx_t *ctx, FILE *out, const char *prefix,
    const char *const *branches, size_t branch_count
) {
    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    if (repo == NULL) return;

    static const struct {
        const char *ref;
        const char *summary;
    } references[] = {
        { "HEAD",   "Current commit"  },
        { "HEAD~1", "Previous commit" },
        { "HEAD~2", "2 commits ago"   },
        { "HEAD~3", "3 commits ago"   },
    };
    for (size_t i = 0; i < sizeof(references) / sizeof(*references); i++) {
        if (prefix) fprintf(out, "%s@", prefix);
        fprintf(out, "%s\t%s\n", references[i].ref, references[i].summary);
    }

    if (branch_count > 0 &&
        commits_walk(repo, out, prefix, branches, branch_count) > 0) {
        return;
    }

    /* None named, or none of them a branch (a positional handed in as a guess
     * may be a path): the enabled histories stand in. */
    const state_profile_entry_t *rows = NULL;
    size_t count = 0;
    error_t *err = state_peek_profiles(state, &rows, &count);
    if (err) {
        error_free(err);
        return;
    }
    const char **enabled = arena_calloc(ctx->arena, count, sizeof(*enabled));
    if (enabled == NULL) return;
    for (size_t i = 0; i < count; i++) {
        enabled[i] = rows[i].name;
    }
    commits_walk(repo, out, prefix, enabled, count);
}

/**
 * The profile a token names
 */
const char *completion_profile_of(const dotta_ctx_t *ctx, const char *token) {
    refspec_t rs = { 0 };
    error_t *err = parse_refspec(ctx->arena, token, &rs);
    if (err) {
        error_free(err);
        return token;
    }
    return rs.profile ? rs.profile : rs.file;
}

/**
 * Commits of the branches named, else of the enabled set
 */
void completion_commits(
    const dotta_ctx_t *ctx, FILE *out,
    char *const *branches, size_t branch_count
) {
    /* The hooks hold `char **` buckets; the walk reads them. C has no implicit
     * widening to a pointer to const pointer to const. */
    commits_emit(ctx, out, NULL, (const char *const *) branches, branch_count);
}

/**
 * Commits of one pinned profile
 */
void completion_history(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
) {
    commits_emit(ctx, out, NULL, &pinned, pinned != NULL ? 1 : 0);
}

/**
 * Commits behind the `@` of a token being typed
 */
bool completion_commits_at(
    const dotta_ctx_t *ctx, FILE *out, const char *current, const char *pinned
) {
    /* The prefix is everything before the last '@'. */
    const char *at = strrchr(current, '@');
    if (at == NULL) return false;

    char *prefix = arena_strndup(ctx->arena, current, (size_t) (at - current));
    if (prefix == NULL) return true;

    const char *branch = pinned ? pinned : completion_profile_of(ctx, prefix);
    commits_emit(ctx, out, prefix, &branch, 1);
    return true;
}

/**
 * Filesystem paths under a relocatable root
 */
bool completion_paths_under(FILE *out, const char *root, const char *current) {
    /* Mirrors path_input_normalize (infra/path.c): no root, a tilde token, or a
     * token already inside the root — the path is what the shell sees. */
    if (root == NULL || root[0] == '\0' || current[0] == '~') return false;

    size_t root_len = strlen(root);
    while (root_len > 0 && root[root_len - 1] == '/') root_len--;
    if (root_len == 0) return false;   /* `--target /` re-roots nothing */

    if (strncmp(current, root, root_len) == 0 &&
        (current[root_len] == '\0' || current[root_len] == '/')) {
        return false;
    }

    /* The token relative to the root keeps its leading-slash style on the way
     * back, so the inserted candidate round-trips the way it was typed. Split
     * it at its last '/': the directory to list under the root, and the name
     * prefix to match in it. */
    const char *leading = current[0] == '/' ? "/" : "";
    const char *rel = current[0] == '/' ? current + 1 : current;
    const char *slash = strrchr(rel, '/');
    size_t dir_len = slash ? (size_t) (slash - rel + 1) : 0;
    const char *name = slash ? slash + 1 : rel;
    size_t name_len = strlen(name);

    char *dir = str_format("%.*s/%.*s", (int) root_len, root, (int) dir_len, rel);
    if (dir == NULL) return true;

    string_array_t *entries = NULL;
    error_t *err = fs_list_dir(dir, &entries);
    if (err) {
        error_free(err);   /* nothing under there: the root applies, nothing to offer */
        free(dir);
        return true;
    }

    for (size_t i = 0; i < entries->count; i++) {
        const char *entry = entries->items[i];
        if (strncmp(entry, name, name_len) != 0) continue;
        if (entry[0] == '.' && name[0] != '.') continue;

        char *path = str_format("%s%s", dir, entry);
        if (path == NULL) continue;
        bool is_dir = fs_is_directory(path);
        free(path);

        fprintf(
            out, "%s%.*s%s%s\n", leading, (int) dir_len, rel, entry,
            is_dir ? "/" : ""
        );
    }

    string_array_free(entries);
    free(dir);
    return true;
}

/**
 * What can stand at the cursor of the line
 */
error_t *cmd_complete(const dotta_ctx_t *ctx, const cmd_complete_options_t *opts) {
    /* The line as argv: the program, then the complete tokens after it. The engine
     * resolves and consumes it and calls the command's hook; outside a repository
     * the hooks' sources stay silent and only native-path requests come back.
     * Nothing to offer is an answer: never an error. */
    int argc = (int) opts->positional_count + 1;
    char **argv = arena_calloc(ctx->arena, (size_t) argc, sizeof(*argv));
    if (argv == NULL) return NULL;
    argv[0] = ctx->argv[0];
    for (int i = 1; i < argc; i++) {
        argv[i] = opts->positional_args[i - 1];
    }
    args_complete_candidates(
        dotta_registry(), argc, argv,
        opts->current ? opts->current : "", ctx->arena, ctx, stdout
    );
    return NULL;
}

/**
 * The completion script for the shell
 */
error_t *cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts) {
    (void) ctx;
    (void) opts;   /* fish — the one shell post_parse admits */

    /* Projects the root registry into the fish dialect, the wrapper calling back
     * into `__complete`. Repo-independent; deterministic on a given binary. The
     * registry is borrowed from main.c via the typed accessor so the cmds/ layer
     * never names the registry symbol. */
    return args_export_completion_fish(
        stdout, dotta_registry(), "dotta", "__complete"
    );
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

static error_t *complete_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_complete(ctx, (const cmd_complete_options_t *) opts_v);
}

static const args_opt_t complete_opts[] = {
    ARGS_STRING(
        "current",              "<token>",
        cmd_complete_options_t, current,
        "The token being typed at the cursor"
    ),
    ARGS_POSITIONAL_RAW(
        cmd_complete_options_t, positional_args,positional_count,
        0,                      0
    ),
    ARGS_END,
};

const args_command_t spec_complete = {
    .name           = "__complete",
    .summary        = "Shell completion helper (hidden)",
    .usage          = "%s __complete [--current=<token>] -- <tokens>...",
    .opts_size      = sizeof(cmd_complete_options_t),
    .opts           = complete_opts,
    .payload        = &(const dotta_needs_t){
        .repo       = DOTTA_REPO_OPEN,
        .state      = DOTTA_STATE_READ,
        .tolerant   = true,
    },
    .dispatch       = complete_dispatch,
    .silent_failure = true,
    .hidden         = true,
};

/**
 * Admit the one shell the engine exports a script for.
 */
static error_t *completion_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_completion_options_t *o = opts_v;

    if (strcmp(o->shell, "fish") != 0) {
        return ERROR(
            ERR_INVALID_ARG, "unknown shell '%s' (fish is the one supported)",
            o->shell
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor: the shell.
 */
static args_want_t completion_complete(
    const void *ctx, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) ctx;
    (void) at;
    const cmd_completion_options_t *o = opts_v;

    if (o->shell == NULL) {
        fputs("fish\tFish shell\n", out);
    }
    return ARGS_WANT_NONE;
}

static error_t *completion_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_completion(ctx, (const cmd_completion_options_t *) opts_v);
}

static const args_opt_t completion_opts[] = {
    ARGS_POSITIONAL_ANY_ARG(
        "<shell>",
        cmd_completion_options_t,shell,  1,
        "The shell to print the script for (fish)"
    ),
    ARGS_END,
};

const args_command_t spec_completion = {
    .name        = "completion",
    .summary     = "Print the shell completion script",
    .usage       = "%s completion <shell>",
    .description =
        "Writes the completion script for <shell> to stdout, generated from\n"
        "this binary's command registry. fish is the one shell supported.\n",
    .examples    =
        "  %s completion fish > ~/.config/fish/completions/dotta.fish\n"
        "  %s completion fish | source       # This session only\n",
    .opts_size   = sizeof(cmd_completion_options_t),
    .opts        = completion_opts,
    .post_parse  = completion_post_parse,
    .complete    = completion_complete,
    .dispatch    = completion_dispatch,
};
