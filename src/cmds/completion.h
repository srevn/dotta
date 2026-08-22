/**
 * completion.h - Shell completion: the candidates and their sources
 *
 * Hidden command answering the shell, and the library of sources every
 * command's `complete` hook draws on. Outputs newline-separated lines to
 * stdout, no stderr output.
 *
 * Design principles:
 * - Silent failures: never print errors, output nothing on failure
 * - Cheap queries: one state read or one view build, never a workspace load
 * - One authority per source: a source reads the enabled set, the view, or Git,
 *   never a blend — a hook composes sources, the library names them
 *
 * Usage:
 *   dotta __complete candidates [--current=<token>] -- <tokens>... What can
 *       stand at the cursor of a command line: <tokens> are the complete ones
 *       after `dotta`, <token> the one being typed. The line is consumed as the
 *       parser would consume it and the command's hook answers
 *       (`args_complete_candidates`). The shell's wrapper, emitted with the
 *       spec, is the caller.
 *   dotta __complete spec fish The fish completion script for the root
 *       registry: the flag and subcommand rules, the condition helpers and the
 *       candidates wrapper. `make completions` writes it to
 *       build/completions/dotta.fish.
 *
 * Outside a repository every source prints nothing and the command exits 0; the
 * shell reads silence as "no candidates". Native path completion is requested
 * through the engine (ARGS_WANT_FILES / ARGS_WANT_DIRS) and needs no
 * repository.
 */

#ifndef DOTTA_CMD_COMPLETION_H
#define DOTTA_CMD_COMPLETION_H

#include <runtime.h>
#include <stdio.h>
#include <types.h>

/**
 * Which profiles a slot admits.
 */
typedef enum {
    COMPLETION_ENABLED,   /* The enabled set, in precedence order */
    COMPLETION_LOCAL,     /* Every local branch, the enabled ones marked */
    COMPLETION_ALL        /* Local branches, then the remote-tracking ones not yet local */
} completion_profiles_t;

/**
 * Profile names.
 *
 * ENABLED is the filter a workspace verb takes; LOCAL is what a verb that names
 * a profile reads or writes; ALL adds what `profile fetch` would download.
 * Branch order is the ref iteration's; the shell sorts.
 */
void completion_profiles(
    const dotta_ctx_t *ctx, FILE *out, completion_profiles_t set
);

/**
 * The view's files: one row per managed path, the winning profile beside it.
 *
 * A winner filter keeps the rows those profiles win — exactly the rows a
 * workspace verb with that filter acts on; a path a filtered profile holds but
 * does not win is not offered because the verb would skip it. Directory rows
 * are metadata claims, not paths the file-taking verbs complete to.
 *
 * @param winners Optional winner filter (NULL/0 for every row)
 */
void completion_files(
    const dotta_ctx_t *ctx, FILE *out,
    char *const *winners, size_t winner_count
);

/**
 * A branch's files, from Git rather than the view, so the verbs that name a
 * profile — remove, list, show, revert, export — reach every file the branch
 * holds: shadowed by a higher profile, or in a profile not enabled here.
 *
 * @param pinned NULL: every local branch, as `<profile>:<path>`. Else that
 *               branch only, as bare `<path>` (the profile is pinned).
 */
void completion_refspecs(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
);

/**
 * The profile a token names: its part before ':' when it is a refspec, the
 * token itself otherwise (its commit part, `profile@commit`, dropped) — what a
 * first positional pins for the verbs that read `[profile:]path` shapes. The
 * refspec parser draws the line, as the commands do. Arena-owned or the token
 * itself; never NULL.
 */
const char *completion_profile_of(const dotta_ctx_t *ctx, const char *token);

/**
 * Commits: the reference forms, valid against any branch, then the recent
 * history of the branches named — one that names no branch contributes nothing
 * — or, when none is named or none is a branch, of the enabled set in
 * precedence order, where show and diff resolve a bare reference. Interleaved
 * histories are labelled by branch.
 */
void completion_commits(
    const dotta_ctx_t *ctx, FILE *out,
    char *const *branches, size_t branch_count
);

/**
 * The history of one pinned profile — the same candidates as
 * `completion_commits` for that branch alone; NULL, or a name that is no branch
 * (a path handed in as a guess), falls through to the enabled histories.
 */
void completion_history(
    const dotta_ctx_t *ctx, FILE *out, const char *pinned
);

/**
 * The commit part of a `<prefix>@<commit>` token being typed: every candidate
 * of `completion_history` as `<prefix>@<token>`, from the history of `pinned`,
 * else of the profile the prefix names (`completion_profile_of`).
 *
 * @return true when `current` carried an `@` and was answered; false when it
 *         did not, and the caller's positional rules apply.
 */
bool completion_commits_at(
    const dotta_ctx_t *ctx, FILE *out, const char *current, const char *pinned
);

/**
 * Configured git remotes, the URL as description.
 */
void completion_remotes(const dotta_ctx_t *ctx, FILE *out);

/**
 * Filesystem paths under a relocatable root, as `add --target` reads them
 * (`path_input_normalize`, infra/path.c): `etc/x` and `/etc/x` both mean
 * `<root>/etc/x`, so the candidates are listed under the root and printed in
 * the style the token was typed in. Dotfiles are offered only when the name
 * being typed starts with '.', as the shell does.
 *
 * @return true when the root applies and the candidates were printed; false
 *         when the path is what the shell sees — no root, a tilde token (HOME's
 *         namespace, never re-rooted), a token already inside the root — and
 *         native completion is the answer.
 */
bool completion_paths_under(FILE *out, const char *root, const char *current);

/**
 * Completion mode.
 *
 * `candidates` depends on the user's repo state; `spec` emits the build-time
 * fish script derived from the root registry — no repo required, output
 * deterministic on a given binary.
 */
typedef enum {
    COMPLETE_CANDIDATES,      /* What can stand at the cursor of a command line */
    COMPLETE_SPEC_FISH        /* Emit the fish completion script (build-time) */
} completion_mode_t;

/**
 * Completion options
 *
 * `mode` is derived by `completion_post_parse` from the first positional token
 * (candidates | spec); `candidates` takes the line's complete tokens as the
 * rest of the bucket, `spec` the dialect.
 */
typedef struct {
    completion_mode_t mode;   /* What to answer */
    const char *current;      /* candidates: the token being typed (--current=) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_completion_options_t;

/**
 * Run completion command
 *
 * Outputs completion results to stdout. Returns NULL on success (even if no
 * results). Never outputs to stderr - silent failure model.
 *
 * @param ctx Dispatch context (ctx->repo is NULL outside a repository)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts);

/**
 * Spec-engine command specification for `dotta __complete`.
 *
 * Hidden from top-level help and from the fish completion export. Registered in
 * main.c's static `dotta_commands[]`; defined in completion.c beside the
 * post_parse and dispatch wrappers.
 */
extern const args_command_t spec_completion;

#endif /* DOTTA_CMD_COMPLETION_H */
