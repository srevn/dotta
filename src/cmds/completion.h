/**
 * completion.h - Shell completion helper
 *
 * Hidden subcommand providing completion data for shell scripts.
 * Outputs newline-separated results to stdout, no stderr output.
 *
 * Design principles:
 * - Silent failures: Never print errors, output nothing on failure
 * - Fast queries: Use state DB for O(1)/O(n) fast lookups
 * - Simple output: Newline-separated for fish consumption
 *
 * Usage:
 *   dotta __complete check                 # Exit 0 if in repo, 1 otherwise
 *   dotta __complete profiles              # Enabled profiles
 *   dotta __complete profiles --all        # All available profiles (branches)
 *   dotta __complete files                 # All managed files
 *   dotta __complete files -p <profile>    # Files in specific profile
 *   dotta __complete files --storage       # Storage paths instead of filesystem
 *   dotta __complete commits               # Recent commits from first enabled profile
 *   dotta __complete commits -p <profile>  # Recent commits from specific profile
 *   dotta __complete commits --limit <n>   # Limit number of commits
 *   dotta __complete spec fish             # Emit the fish completion script for
 *                                          #   the entire root registry. Used by
 *                                          #   the Makefile to regenerate the
 *                                          #   dotta-completions.fish snapshot.
 */

#ifndef DOTTA_CMD_COMPLETION_H
#define DOTTA_CMD_COMPLETION_H

#include <runtime.h>
#include <types.h>

/**
 * Completion mode.
 *
 * Runtime modes (check / profiles / files / commits / remotes) emit
 * data that depends on the user's repo state. `spec` modes emit the
 * build-time fish script derived from the root command registry — no
 * repo required, output is deterministic on a given binary.
 */
typedef enum {
    COMPLETE_CHECK,           /* Check if in dotta repo (exit 0/1) */
    COMPLETE_PROFILES,        /* List profiles (enabled or all) */
    COMPLETE_FILES,           /* List managed files */
    COMPLETE_COMMITS,         /* List recent commits */
    COMPLETE_REMOTES,         /* List git remotes */
    COMPLETE_SPEC_FISH,       /* Emit fish completion script (build-time) */
} completion_mode_t;

/**
 * Completion options
 *
 * `mode` is derived by `completion_post_parse` from the first positional
 * token (check | profiles | files | commits | remotes).
 */
typedef struct {
    /* User-facing (read by cmd_completion). */
    completion_mode_t mode;   /* What to complete */
    const char *profile;      /* Optional: filter by profile */
    bool all;                 /* For profiles: include all (not just enabled) */
    bool storage_paths;       /* For files: output storage_path instead of filesystem_path */
    long limit;               /* For commits: max results (default 20) */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_completion_options_t;

/**
 * Run completion command
 *
 * Outputs completion results to stdout.
 * Returns NULL on success (even if no results).
 * Never outputs to stderr - silent failure model.
 *
 * @param ctx Dispatch context (ctx->repo may be NULL for COMPLETE_CHECK mode)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_completion(const dotta_ctx_t *ctx, const cmd_completion_options_t *opts);

/**
 * Spec-engine command specification for `dotta __complete`.
 *
 * Hidden from top-level help and from the fish completion export.
 * Registered in main.c's static `dotta_commands[]`; defined in
 * completion.c beside the post_parse and dispatch wrappers.
 */
extern const args_command_t spec_completion;

#endif /* DOTTA_CMD_COMPLETION_H */
