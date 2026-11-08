/**
 * completion.c - Shell completion: the script, the candidates and their sources
 *
 * `dotta __complete` answers the shell's question — what can stand at the cursor
 * of a command line — through the spec engine: the line is consumed as the parser
 * would consume it, and the command's `complete` hook prints what its grammar
 * admits at that position. The sources the hooks draw on live here, one authority
 * each: the enabled set (state), the view (every enabled profile at HEAD,
 * precedence resolved), Git (a branch's tree or history, or one path's changes
 * in it), or the filesystem (the paths a re-rooting flag reads under). The hooks
 * compose them per command; nothing here guesses which one a command wants. `dotta
 * completion <shell>` prints the script that asks.
 *
 * The sources fail silently: errors result in no output rather than messages to
 * stderr, and outside a repository every source prints nothing.
 */

#include "cmds/completion.h"

#include <stdio.h>
#include <string.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/refspec.h"
#include "base/string.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "core/state.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/remote.h"
#include "sys/stats.h"

/* Emission limits */
#define COMPLETE_COMMIT_SHORT_OID_LEN 8
#define COMPLETE_COMMIT_LIMIT 20
#define COMPLETE_COMMIT_SUMMARY_MAX 60

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
        state_profiles_t rows = state_profiles(state);
        for (size_t i = 0; i < rows.count; i++) {
            fprintf(out, "%s\tEnabled profile\n", rows.entries[i].name);
        }
        return;
    }

    /* A listing that failed offers no local name, and the remote's may still; a
     * state the tolerant open could not load marks none of them enabled. A failed
     * listing leaves the array as it was: empty, read by the remote's offers
     * below as nothing here. */
    string_array_t profiles = { 0 };
    error_t err = gitops_list_branches(repo, ctx->arena, &profiles);
    if (!err) {
        for (size_t i = 0; i < profiles.count; i++) {
            const char *profile = profiles.entries[i];
            fprintf(
                out, "%s\t%s\n", profile,
                state && state_enabled(state, profile) ? "Enabled profile"
                                                       : "Available profile"
            );
        }
    }

    if (set == COMPLETION_ALL) {
        /* A remote the fetch would meet, or nothing to download: none configured,
         * or several with no origin, and the fetch refuses before any name */
        const char *remote_name = NULL;
        err = remote_default(repo, ctx->arena, &remote_name);
        if (err) return;

        /* What the remote's last contact listed (sys/remote.h
         * remote_last_branches), less what is here already: no network in a
         * completion, so a profile created there since its last contact is not
         * offered, and one deleted there since is offered and refused by the
         * fetch. */
        const string_array_t remote_names = remote_last_branches(repo, ctx->arena);
        for (size_t i = 0; i < remote_names.count; i++) {
            if (string_array_contains(&profiles, remote_names.entries[i])) continue;
            fprintf(out, "%s\tRemote profile\n", remote_names.entries[i]);
        }
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

        /* A remote with no URL is described by its kind, and so is one whose
         * lookup fails; the URL is read off the configuration as it stands, before
         * the remote goes */
        git_remote *remote = NULL;
        const char *url = NULL;
        if (git_remote_lookup(&remote, repo, name) == 0) url = git_remote_url(remote);
        fprintf(out, "%s\t%s\n", name, url ? url : "Remote");
        git_remote_free(remote);
    }

    git_strarray_dispose(&remotes);
}

/**
 * The view's files and its directory claims, slash-marked, narrowed to the winners
 * named
 *
 * Directory claims are offered whichever class they are: an ancestor claim is
 * an active path, and the update remedy ('dotta update <dir>') names exactly
 * such a path — a completer that hid the spine would hide the cure. The layer's
 * rung is offered with them, an active path apply converges, under the name its
 * profile would give the place and holds no claim at (core/manifest.h
 * manifest_holds_row).
 */
void completion_files(
    const dotta_ctx_t *ctx, FILE *out, char *const *winners, size_t winner_count
) {
    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    /* The view needs both, and a tolerant open (runtime.h) may leave either
     * NULL: no store here, or a database that would not load. */
    if (repo == NULL || state == NULL) return;

    /* The full view per request is priced and fine: ~10 ms end-to-end for the
     * whole `dotta __complete` invocation (process start included) on a 4-profile
     * / ~180-row repository, measured 2026-08 — well inside a tab-press. */
    manifest_t *manifest = NULL;
    error_t err = manifest_build(repo, state, ctx->arena, &manifest);
    if (err) {
        return;
    }

    manifest_rows_t rows = manifest_rows(manifest);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

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
}

/**
 * What a directory offer prints beside each claim: where the candidates go, and
 * the profile they are offered from
 */
typedef struct {
    FILE *out;
    const char *profile;   /* Each candidate's description */
} completion_offer_t;

/**
 * Walk visitor: one claim, offered slash-marked where it is a directory's — a
 * file claim is the refspecs' to offer (completion_refspecs)
 *
 * @param claim One claim, decoded (borrowed — valid for the call only)
 * @param payload The offer (completion_offer_t)
 * @return NULL: an offer fails nowhere
 */
static error_t completion_offer_directory(const profile_claim_t *claim, void *payload) {
    const completion_offer_t *offer = payload;

    if (claim->type == PATH_TYPE_DIRECTORY) {
        fprintf(offer->out, "%s/\t%s\n", claim->storage_path, offer->profile);
    }

    return NULL;
}

/**
 * A profile's directory claims, read from its walk rather than the view
 *
 * Either class, deliberately — see completion_files.
 */
void completion_directories(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
) {
    git_repository *repo = ctx->run.repo;
    if (repo == NULL || pinned == NULL) return;

    /* The profile at its head: not a branch, or a head that will not read, offers
     * nothing */
    profile_t *profile = NULL;
    error_t err = profile_load(repo, pinned, &profile);
    if (err) return;

    /* The directory claims the walk shows, so a claim a blob contradicts at its
     * own name or above it is none, and is not offered. Read strictly: the claims
     * are the sheet's alone, so a sheet that will not load offers none either
     * way, and a strict walk spares the tree. They come after the tree's blobs,
     * so a walk that fails offers none of them; its failure is dropped, as the
     * load's above, at most one per offer */
    completion_offer_t offer = { .out = out, .profile = pinned };
    (void) profile_walk(profile, PROFILE_READ_STRICT, completion_offer_directory, &offer);
    profile_free(profile);
}

/* The refspec walk: where the tokens go. */
typedef struct {
    FILE *out;
    const char *profile;  /* current profile (source of the "<profile>:" prefix) */
    bool prefix;          /* prefix "<profile>:" (every profile) vs bare path (pinned) */
} refspec_walk_t;

/**
 * Walk visitor: one token per tracked file blob
 *
 * The content gate every walk over a branch asks (infra/label.h label_prefixes),
 * of every entry's whole name: a name in the grammar is content, and whatever
 * else a branch holds — a top-level blob under no label, .dotta/, whatever a
 * hand left beside them — is one of its internal files, pruned with its subtree
 * and no token.
 */
static error_t refspec_emit(
    const char *path, const git_tree_entry *entry, void *payload,
    gitops_next_t *next
) {
    const refspec_walk_t *walk = payload;

    if (!label_prefixes(path)) {                                  /* the content gate */
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }
    if (git_tree_entry_type(entry) != GIT_OBJECT_BLOB) return NULL;  /* descend trees */

    if (walk->prefix) {
        fprintf(walk->out, "%s:%s\n", walk->profile, path);
    } else {
        fprintf(walk->out, "%s\t%s\n", path, walk->profile);
    }
    return NULL;
}

/**
 * A profile's files, read from Git rather than the view
 */
void completion_refspecs(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
) {
    git_repository *repo = ctx->run.repo;
    if (repo == NULL) return;

    string_array_t profiles;
    if (pinned) {
        string_array_init(&profiles, ctx->arena, 0);
        string_array_push(&profiles, pinned);
    } else {
        error_t err = gitops_list_branches(repo, ctx->arena, &profiles);
        if (err) return;  /* silent-failure model */
    }

    refspec_walk_t walk = {
        .out    = out,
        .prefix = (pinned == NULL)
    };

    /* Every profile's tree, whole: the shell matches what is typed against all
     * of it, its substring and subsequence matches among them, and sorts what
     * it offers */
    for (size_t i = 0; i < profiles.count; i++) {
        const char *profile = profiles.entries[i];

        git_tree *tree = NULL;
        error_t err = gitops_load_branch_tree(repo, profile, &tree);
        if (err) continue;  /* not a branch, or unloadable: silent */

        walk.profile = profile;
        /* A walk's failure is silent here, as the load's above: at most one per
         * profile is dropped */
        (void) gitops_tree_walk(tree, refspec_emit, &walk);
        git_tree_free(tree);
    }
}

/**
 * The reference forms, valid against any branch: its head and the head's first
 * three steps, `<prefix>@` before each where a prefix is given
 */
static void commits_references(FILE *out, const char *prefix) {
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
}

/**
 * One branch's recent commits, from its head, up to the per-branch limit; a name
 * that resolves to no branch offers nothing. `prefix`, when given, is printed
 * before every token as `<prefix>@<token>`. Where several histories are listed
 * together, each description carries its branch so the interleaved hashes stay
 * attributable.
 *
 * @return Number of commits offered
 */
static size_t commits_walk(
    const dotta_ctx_t *ctx, FILE *out, const char *prefix, const char *profile,
    bool interleaved
) {
    git_repository *repo = ctx->run.repo;

    /* The branch's head, as every verb that takes one of these commits reads it
     * (sys/gitops.h gitops_load_branch_commit) — never a DWIM, whose tag of the
     * same name would win and offer commits no branch holds. A name that is no
     * branch, or a head that will not read, offers nothing. */
    git_commit *head = NULL;
    error_t err = gitops_load_branch_commit(repo, profile, &head);
    if (err) return 0;

    /* The history from that head in git's order, newest first, each commit's
     * parents read as it is passed: libgit2's unsorted walk inserts them by date
     * (revwalk.c get_revision), as git log does (lib/git/revision.c get_revision_1)
     * and sys/revision.c revision_search walks — so a TAB reads the commits it
     * offers, where a sort reads every commit the head reaches before the first
     * (revwalk.c limit_list). Which commits are offered is the walk's; the order
     * they show in is the shell's, which sorts. A commit whose parent will not
     * parse is never yielded, and the offer ends there. The push copies the head's
     * id, so the head is freed once it is taken. */
    git_revwalk *walker = NULL;
    int rc = git_revwalk_new(&walker, repo);
    if (rc == 0) rc = git_revwalk_push(walker, git_commit_id(head));
    git_commit_free(head);

    size_t offered = 0;
    git_oid oid;
    while (rc == 0 && offered < COMPLETE_COMMIT_LIMIT && git_revwalk_next(&oid, walker) == 0) {
        git_commit *commit = NULL;
        if (git_commit_lookup(&commit, repo, &oid) != 0) {
            continue;
        }

        /* Format short OID */
        char oid_str[COMPLETE_COMMIT_SHORT_OID_LEN + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &oid);

        /* The summary every screen reads (sys/stats.h stats_commit_info), as a
         * terminal may show it, cut on a whole character (base/string.h
         * str_display) */
        const commit_info_t info = stats_commit_info(ctx->arena, commit);
        char summary[COMPLETE_COMMIT_SUMMARY_MAX + 1];
        str_display(summary, sizeof(summary), info.summary, strlen(info.summary));

        if (prefix) fprintf(out, "%s@", prefix);
        if (interleaved) {
            fprintf(out, "%s\t%s: %s\n", oid_str, profile, summary);
        } else {
            fprintf(out, "%s\t%s\n", oid_str, summary);
        }

        git_commit_free(commit);
        offered++;
    }

    git_revwalk_free(walker);    /* NULL-safe: revwalk.c git_revwalk_free */
    return offered;
}

/**
 * The commit candidates: the reference forms first, then the named histories,
 * else the enabled ones.
 */
static void commits_emit(
    const dotta_ctx_t *ctx, FILE *out, const char *const *profiles, size_t profile_count
) {
    if (ctx->run.repo == NULL) return;

    commits_references(out, NULL);

    /* The branches named, each its own history */
    size_t offered = 0;
    for (size_t i = 0; i < profile_count; i++) {
        offered += commits_walk(ctx, out, NULL, profiles[i], profile_count > 1);
    }
    if (offered > 0) return;

    /* None named, or none of them a branch (a positional handed in as a guess
     * may be a path): the enabled histories stand in, in precedence order, each
     * row's name as the row holds it. */
    state_profiles_t rows = state_profiles(ctx->run.state);
    for (size_t i = 0; i < rows.count; i++) {
        commits_walk(ctx, out, NULL, rows.entries[i].name, rows.count > 1);
    }
}

/**
 * The commits that changed one path of one profile, newest first, `<prefix>@`
 * before each where a prefix is given: the argument read as the commands read
 * one, the profile's name for it at its head, and the walk of its lines from
 * that head. An argument that does not read, a name that is no branch, or a head,
 * a sheet or a walk that will not read, offers nothing.
 */
static void changes_emit(
    const dotta_ctx_t *ctx, FILE *out, const char *prefix, const char *name,
    const char *path
) {
    git_repository *repo = ctx->run.repo;
    const mount_table_t *mounts = ctx->run.mounts;
    if (repo == NULL || mounts == NULL) return;

    /* The argument first, in the key it names (infra/path.h): one the commands
     * refuse offers nothing, and nothing is read for it */
    path_input_t arg;
    error_t err = path_input_resolve(path, ctx->arena, &arg);
    if (err) return;

    /* The branch's head, read once, as commits_walk reads it: the name the path
     * is given and the history behind it are that one commit's. The id is kept
     * and the commit let go once the profile is opened at it. */
    git_commit *head = NULL;
    err = gitops_load_branch_commit(repo, name, &head);
    if (err) return;

    git_oid head_oid;
    git_oid_cpy(&head_oid, git_commit_id(head));
    profile_t *profile = NULL;
    err = profile_open(name, head, &profile);
    git_commit_free(head);
    if (err) return;

    /* The profile at the head names the path (core/scope.h scope_resolve_name):
     * a name as typed, a path its own view's */
    const char *storage_path = NULL;
    err = scope_resolve_name(profile, mounts, &arg, ctx->arena, &storage_path);
    profile_free(profile);
    if (err) return;

    /* Its changes from that head, a file's or everything beneath a directory's
     * (sys/stats.h stats_path_history), each printed as commits_walk prints one */
    path_history_t history;
    err = stats_path_history(repo, &head_oid, storage_path, ctx->arena, &history);
    if (err) return;

    for (size_t i = 0; i < history.count; i++) {
        const commit_info_t *commit = &history.commits[i];

        char oid_str[COMPLETE_COMMIT_SHORT_OID_LEN + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &commit->oid);
        char summary[COMPLETE_COMMIT_SUMMARY_MAX + 1];
        str_display(summary, sizeof(summary), commit->summary, strlen(commit->summary));

        if (prefix) fprintf(out, "%s@", prefix);
        fprintf(out, "%s\t%s\n", oid_str, summary);
    }
}

/**
 * The profile a token names
 */
const char *completion_profile_of(const dotta_ctx_t *ctx, const char *token) {
    refspec_t rs = { 0 };
    error_t err = refspec_parse(ctx->arena, token, &rs);
    if (err) {
        return token;
    }
    return rs.profile ? rs.profile : rs.file;
}

/**
 * Commits of the branches named, else of the enabled set
 */
void completion_commits(
    const dotta_ctx_t *ctx, FILE *out,
    char *const *profiles, size_t profile_count
) {
    /* The hooks hold `char **` buckets; the walk reads them. C has no implicit
     * widening to a pointer to const pointer to const. */
    commits_emit(ctx, out, (const char *const *) profiles, profile_count);
}

/**
 * Commits of one pinned profile
 */
void completion_history(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
) {
    commits_emit(ctx, out, &pinned, pinned != NULL ? 1 : 0);
}

/**
 * The commits that changed the path a word names
 */
bool completion_path_history(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned, const char *token
) {
    /* The word read as the commands read it (base/refspec.h): one they refuse,
     * or one that names its commit already, leaves no commit slot after it */
    refspec_t rs = { 0 };
    if (refspec_parse(ctx->arena, token, &rs) != NULL || rs.commit != NULL) return true;

    /* Its profile, else the one the line pinned: none, and the caller's rules
     * stand */
    const char *profile = rs.profile ? rs.profile : pinned;
    if (profile == NULL) return false;

    changes_emit(ctx, out, NULL, profile, rs.file);
    return true;
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
    if (ctx->run.repo == NULL) return true;

    /* Read as the commands read it (base/refspec.h): a prefix they refuse, or
     * one whose last '@' is its commit's own — a reflog's HEAD@{ being typed —
     * leaves no commit to offer */
    char *prefix = arena_strndup(ctx->arena, current, (size_t) (at - current));
    refspec_t rs = { 0 };
    if (refspec_parse(ctx->arena, prefix, &rs) != NULL || rs.commit != NULL) return true;

    /* Its profile, else the one the line pinned: with a path, the path's own
     * changes. A prefix that announces no path is the profile itself: its history
     * alone, and the reference forms beside it only where it is a branch — the
     * walk's count says so, as commits_emit reads it — so a name that is no branch
     * offers nothing. The shell sorts every candidate (cmds/completion.h), so
     * the forms printed after the walk read as they would before it. */
    const char *profile = rs.profile ? rs.profile : pinned;
    if (profile) {
        changes_emit(ctx, out, prefix, profile, rs.file);
    } else if (!path_input_announces_path(rs.file)) {
        if (commits_walk(ctx, out, prefix, rs.file, false) > 0) {
            commits_references(out, prefix);
        }
    }

    return true;
}

/**
 * Filesystem paths under a relocatable root
 */
bool completion_paths_under(
    const dotta_ctx_t *ctx, FILE *out, const char *profile, const char *target,
    const char *current
) {
    /* Mirrors add_spell (cmds/add.c): no flag, a tilde token, or a token spelled
     * from here — the path is what the shell sees. A saved binding alone re-roots
     * nothing: without the flag the command reads an argument where it was typed,
     * so there is no root here either. */
    if (target == NULL || target[0] == '\0' ||
        current[0] == '~' || current[0] == '.') {
        return false;
    }

    /* The flag as the command reads it — absolute, or relative to the working
     * directory the shell completes in (infra/path.h) — so the token is compared
     * against an absolute root, and the row's spelling against the flag's as
     * the binders compare them. The arena's, as every reader of a filesystem
     * key is, so the two spellings the root may take are one borrowed pointer
     * with nothing to free between them. A flag that will not read leaves the
     * completion with no root of its own to offer beneath, so the shell's own
     * files stand. */
    const char *root = NULL;
    error_t err = path_input_filesystem_path(target, ctx->arena, &root);
    if (err) {
        return false;
    }

    /* The row's spelling wherever the profile is bound at the flag's directory:
     * cmd_add takes it before it reads an argument and says so in a line, so a
     * token the command reads is one spelled under the row's, and the flag's
     * spelling of that same directory is outside by string and re-rooted
     * (add_inside). Bound elsewhere the command refuses the add and the offer
     * is the flag's — what the user is looking at; bound nowhere, the flag is
     * the binding. The compare is the binders' own (mount_same_target): two stats
     * beside the process start, the repository open and the state load a keystroke
     * already pays, and none at all where the row is spelled as the flag is.
     * Only the test below reads the spelling — one directory lists alike — so
     * the substitution shows on an absolute token alone. Borrowed from the row
     * cache, which nothing here moves (core/state.h); NULL outside a repository,
     * where there is no row to ask. */
    const char *bound = state_target(ctx->run.state, profile);
    if (bound && mount_same_target(bound, root)) root = bound;

    /* At the root or beneath it the command reads the token as typed, so the
     * path is the shell's: add_spell's escape test over the same two strings,
     * positive (base/string.h str_path_under). Every absolute token lies under
     * a root of "/", and a relative one lists beneath it. */
    if (str_path_under(current, root, strlen(root))) {
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

    /* The listing and every path built from it are the arena's and abandoned,
     * the module's idiom (cmds/add.c add_inside): nothing here is freed, so no
     * candidate's path has a free to get wrong. The token's directory is joined
     * beneath the root as the command joins an argument there (add_spell), one
     * separator at the seam, the root directory's own included (base/string.h
     * str_path_join). */
    const char *dir = dir_len > 0
        ? str_path_join(ctx->arena, root, arena_strndup(ctx->arena, rel, dir_len))
        : root;

    string_array_t listing;
    err = fs_list_dir(dir, ctx->arena, &listing);
    if (err) return true;   /* nothing under there: the root applies, nothing to offer */

    for (size_t i = 0; i < listing.count; i++) {
        const char *entry = listing.entries[i];
        if (strncmp(entry, name, name_len) != 0) continue;
        if (entry[0] == '.' && name[0] != '.') continue;

        const char *path = str_path_join(ctx->arena, dir, entry);

        fprintf(
            out, "%s%.*s%s%s\n", leading, (int) dir_len, rel, entry,
            fs_is_directory(path) ? "/" : ""
        );
    }

    return true;
}

/**
 * What can stand at the cursor of the line
 */
error_t cmd_complete(const dotta_ctx_t *ctx, const cmd_complete_options_t *opts) {
    /* The line as argv: the program, then the complete tokens after it. The engine
     * resolves and consumes it and calls the command's hook; outside a repository
     * the hooks' sources stay silent and only native-path requests come back.
     * Nothing to offer is an answer: never an error. */
    int argc = (int) opts->positional_count + 1;
    char **argv = arena_calloc(ctx->arena, (size_t) argc, sizeof(*argv));
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
error_t cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts) {
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

static error_t complete_dispatch(const void *ctx_v, void *opts_v) {
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
        .mounts     = true,
        .tolerant   = true,
    },
    .dispatch       = complete_dispatch,
    .silent_failure = true,
    .hidden         = true,
};

/**
 * Admit the one shell the engine exports a script for.
 */
static error_t completion_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    const cmd_completion_options_t *o = opts_v;

    if (strcmp(o->shell, "fish") != 0) {
        return error_create(
            ERR_INVALID_ARG, "Unknown shell '%s' (fish is the one supported)",
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

static error_t completion_dispatch(const void *ctx_v, void *opts_v) {
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
