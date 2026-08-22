/**
 * completion.h - Shell completion helper
 *
 * Hidden subcommand providing completion data for shell scripts. Outputs
 * newline-separated results to stdout, no stderr output.
 *
 * Design principles:
 * - Silent failures: Never print errors, output nothing on failure
 * - Cheap queries: one state read or one view build, never a workspace load
 * - Simple output: Newline-separated for fish consumption
 * - One authority per mode: a mode reads the enabled set, the view, or Git,
 *   never a blend — the shell composes sources, the binary names them
 *
 * Usage:
 *   dotta __complete profiles                 # The enabled set, in precedence order
 *   dotta __complete profiles --local         # Every local branch (enabled ones marked)
 *   dotta __complete profiles --remote        # Remote-tracking branches without a local
 *   dotta __complete files                    # The view: every managed file, with its winner
 *   dotta __complete files -p X [-p Y]        # The view's rows won by X (or Y)
 *   dotta __complete refspecs                 # Every local branch's files as profile:path
 *   dotta __complete refspecs -p X            # Branch X's files, bare (the profile is pinned)
 *   dotta __complete commits                  # Recent commits of the enabled set, in order
 *   dotta __complete commits -p X [-p Y]      # Recent commits of branch X (and Y)
 *   dotta __complete commits --limit <n>      # Cap per branch (default 20)
 *   dotta __complete remotes                  # Configured git remotes
 *   dotta __complete spec fish                # Emit the fish completion script for
 *                                             #   the entire root registry. Used by
 *                                             #   the Makefile to generate
 *                                             #   dotta-completions.fish at install time.
 *
 * Outside a repository every data mode prints nothing and exits 0; the shell
 * reads silence as "no candidates".
 */

#ifndef DOTTA_CMD_COMPLETION_H
#define DOTTA_CMD_COMPLETION_H

#include <runtime.h>
#include <types.h>

/**
 * Completion mode.
 *
 * Runtime modes (profiles / files / refspecs / commits / remotes) emit data that
 * depends on the user's repo state. `spec` modes emit the build-time fish script
 * derived from the root command registry — no repo required, output is
 * deterministic on a given binary.
 */
typedef enum {
    COMPLETE_PROFILES,        /* Profile names (enabled, local, remote) */
    COMPLETE_FILES,           /* The view's file rows */
    COMPLETE_REFSPECS,        /* Git trees: files of every branch, or of one */
    COMPLETE_COMMITS,         /* Recent commits of one or more branches */
    COMPLETE_REMOTES,         /* Git remotes */
    COMPLETE_SPEC_FISH,       /* Emit fish completion script (build-time) */
} completion_mode_t;

/**
 * Completion options
 *
 * `mode` is derived by `completion_post_parse` from the first positional token
 * (profiles | files | refspecs | commits | remotes | spec). Each flag belongs to
 * the modes that read it; post_parse rejects it elsewhere so a stray flag never
 * passes silently.
 */
typedef struct {
    /* User-facing (read by cmd_completion). */
    completion_mode_t mode;   /* What to complete */
    bool local;               /* profiles: every local branch */
    bool remote;              /* profiles: remote-tracking branches without a local */
    char **profiles;          /* -p (repeatable): the view's winners (files), the
                               * branches to walk (commits), the one branch pinned
                               * (refspecs) */
    size_t profile_count;
    long limit;               /* commits: max results per branch (default 20) */

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
 * main.c's static `dotta_commands[]`; defined in completion.c beside the post_parse
 * and dispatch wrappers.
 */
extern const args_command_t spec_completion;

#endif /* DOTTA_CMD_COMPLETION_H */
