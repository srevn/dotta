/**
 * completion.h - Shell completion: the script, the candidates and their sources
 *
 * Two commands with opposite contracts, and the library of sources every
 * command's `complete` hook draws on:
 *
 *   dotta completion <shell>
 *       Prints the completion script for <shell> — fish is the one supported
 *       — generated from this binary's command registry: the flag and
 *       subcommand rules, the condition helpers and the wrapper that asks
 *       `dotta __complete`. Build-time, no repository; a registry name the
 *       script cannot carry as a shell word is an error, reported.
 *       `make completions` writes it to build/completions/dotta.fish.
 *
 *   dotta __complete [--current=<token>] -- <tokens>...
 *       Hidden. What can stand at the cursor of a command line: <tokens> are
 *       the complete ones after `dotta`, <token> the one being typed. The line
 *       is consumed as the parser would consume it and the command's hook
 *       answers (`args_complete_candidates`). The script's wrapper is the
 *       caller, and it reads silence as "no candidates": never an error
 *       message, nothing on failure, exit 0 outside a repository — where every
 *       source prints nothing, and only native path requests (ARGS_WANT_FILES
 *       / ARGS_WANT_DIRS), which need none, come back.
 *
 * The sources print newline-separated candidates to a stream, one authority
 * each: a source reads the enabled set, the view, or Git, never a blend — a
 * hook composes sources, the library names them. One state read or one view
 * build, never a workspace load.
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
 * ride along slash-marked when asked for — a directory claim is a subtree
 * filter with prefix semantics for the verbs that act on it (apply, update,
 * diff); the file-only form serves the slots with nothing to show for one
 * (list's history).
 *
 * @param winners     Optional winner filter (NULL/0 for every row)
 * @param directories Offer the view's directory claims too, slash-marked
 */
void completion_files(
    const dotta_ctx_t *ctx, FILE *out,
    char *const *winners, size_t winner_count, bool directories
);

/**
 * A branch's directory claims, from its metadata rather than the view — the
 * companion of completion_refspecs' pinned form for the verbs that act on a
 * branch's claims (remove untracks them, export materializes them): bare
 * slash-marked paths, the branch as description. An empty tracked directory
 * (no tree entry) is exactly as offerable as the rest.
 */
void completion_directories(
    const dotta_ctx_t *ctx, FILE *out, const char *branch
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
 * `dotta __complete` options: the line, as the shell's wrapper passes it.
 */
typedef struct {
    const char *current;      /* The token being typed (--current=); NULL when none */

    /* The complete tokens after the program, after `--`. */
    char **positional_args;
    size_t positional_count;
} cmd_complete_options_t;

/**
 * Print what can stand at the cursor of the line in `opts` to stdout.
 *
 * Returns NULL whatever happens — even nothing to offer is an answer, and the
 * shell's wrapper must never see an error.
 *
 * @param ctx Dispatch context (ctx->run.repo is NULL outside a repository)
 * @param opts Command options (must not be NULL)
 */
error_t *cmd_complete(const dotta_ctx_t *ctx, const cmd_complete_options_t *opts);

/**
 * Spec-engine command specification for `dotta __complete`.
 *
 * Hidden from top-level help and from the completion export; silent on
 * failure. Registered in main.c's static `dotta_commands[]`; defined in
 * completion.c beside the dispatch wrapper.
 */
extern const args_command_t spec_complete;

/**
 * `dotta completion` options.
 */
typedef struct {
    const char *shell;        /* The shell to print the script for: fish */
} cmd_completion_options_t;

/**
 * Print the completion script for `opts->shell` to stdout.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL; the shell admitted by post_parse)
 * @return Error when the registry holds a name the script cannot carry, or NULL
 */
error_t *cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts);

/**
 * Spec-engine command specification for `dotta completion`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in completion.c
 * beside the post_parse and dispatch wrappers.
 */
extern const args_command_t spec_completion;

#endif /* DOTTA_CMD_COMPLETION_H */
