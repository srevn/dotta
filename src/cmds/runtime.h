/**
 * runtime.h - Dotta-side adapter for the spec-engine
 *
 * The base/args parser engine is domain-free: it knows how to parse
 * argv, render help, emit fish completion, and dispatch to a handler.
 * Everything dotta-specific that the engine needs to thread through to
 * commands lives here:
 *
 *   - `dotta_repo_mode_t` — repo-open contract for the dispatcher;
 *   - `dotta_spec_ext_t`  — payload referenced by `args_command_t::user_data`,
 *                           letting each command declare its repo mode in
 *                           a typed way without the engine learning the enum;
 *   - `dotta_ctx_t`       — bundle handed to each command's dispatch
 *                           handler (repo, config, output, arena, ...);
 *   - four `dotta_ext_*` constants — one per repo mode; commands point
 *                           `user_data` at the constant matching their need.
 *
 * The root-command registry (the NULL-terminated `args_command_t *const []`)
 * lives as `static` data inside main.c and is borrowed into each
 * `dotta_ctx_t::commands`. This keeps the cmds/ layer free of any
 * compile-time dependency on the registry symbol — the only command
 * that needs to enumerate it (`__complete spec fish`) reads it through
 * the ctx like any other dispatch input.
 */

#ifndef DOTTA_CMD_RUNTIME_H
#define DOTTA_CMD_RUNTIME_H

#include <types.h>          /* error_t, arena_t, config_t, output_ctx_t */

#include "base/args.h"      /* args_command_t (used by ctx->commands) */

/* libgit2's opaque repo type. Consumers that touch the pointer must
 * `#include <git2.h>` for the API; this header stays free of the
 * libgit2 dependency so it can be included transitively without
 * forcing every TU through git2.h. */
struct git_repository;

/**
 * Repository-opening contract honored by the dispatcher.
 *
 * Each command declares its repo needs via a `dotta_spec_ext_t` payload
 * pointed at by `args_command_t::user_data`. Main.c reads the mode in
 * `run_spec` and opens the repo (or not) accordingly before dispatch.
 */
typedef enum dotta_repo_mode {
    DOTTA_REPO_NONE,            /* No repo handle needed */
    DOTTA_REPO_REQUIRED,        /* Error if repo_open fails */
    DOTTA_REPO_OPTIONAL_SILENT, /* NULL on failure; no error reported */
    DOTTA_REPO_PATH_ONLY        /* Resolve path, hand it via ctx->repo_path */
} dotta_repo_mode_t;

/**
 * Per-command extension payload referenced by `args_command_t::user_data`.
 *
 * Today this only carries the repo-open mode, but it exists as a struct
 * (rather than a bare enum cast) so future per-command dispatch flags
 * (privilege escalation, quiet-stderr override, etc.) land here as
 * additional fields without touching the engine.
 */
typedef struct dotta_spec_ext {
    dotta_repo_mode_t repo_mode;
} dotta_spec_ext_t;

/**
 * Dispatch context — populated by the dispatcher, read by each command.
 *
 * Bundling is deliberate: future additions (signal cancellation, state
 * cache handle, etc.) land as struct members, not dispatch-signature
 * churn across every command.
 *
 * Field lifetimes
 * ---------------
 *   `repo` / `repo_path` / `arena`   — command-scoped (created in
 *                                      run_spec, destroyed on return).
 *   `config` / `out`                  — process-scoped (created in main).
 *   `argc` / `argv`                   — process-scoped (kernel-supplied).
 *   `exit_code`                       — points to a stack int in run_spec;
 *                                      command-scoped lifetime.
 *   `commands`                        — process-scoped (static array in
 *                                      main.c). Borrowed; never freed.
 *
 * Exit-code override
 * ------------------
 * Dispatch returns `error_t *` — dotta's native failure channel. For
 * native commands a non-NULL error collapses to process exit `1` and a
 * NULL error collapses to `0`; the single bit is enough.
 *
 * Pass-through commands (e.g. `dotta git`) run an external tool whose
 * *exact* exit status is the contract users rely on (`git diff
 * --exit-code` returns 1 on diffs, 128+n on signals, etc.). They
 * assign `*ctx->exit_code` to the value they want dotta to exit with
 * and return `NULL` from dispatch. Main honors that value when no
 * error is reported; otherwise the error path wins.
 *
 * The runner owns the int: `run_spec` allocates it on its frame,
 * initializes it to 0, and points `exit_code` at it. This keeps `ctx`
 * const-honest — the struct's pointer field never mutates, only the
 * pointee does, which was never const. Native commands that never
 * touch the pointer leave the runner at 0 and exit cleanly.
 */
typedef struct dotta_ctx {
    struct git_repository *repo;        /* NULL unless repo_mode opens */
    const char *repo_path;              /* Set iff DOTTA_REPO_PATH_ONLY */
    const config_t *config;
    output_ctx_t *out;
    arena_t *arena;                        /* Command-scoped; parser-owned */
    int argc;                              /* Original process argc */
    char **argv;                           /* Original process argv */
    int *exit_code;                        /* Non-NULL; *exit_code overrides exit when err==NULL */
    const args_command_t *const *commands; /* Borrowed root registry; NULL-terminated */
} dotta_ctx_t;

/* Per-mode payloads. Each command's spec sets `.user_data = &dotta_ext_X`
 * for the matching mode; main.c reads it back in run_spec. The four
 * constants live in runtime.c — referenced from every command file but
 * defined exactly once. */
extern const dotta_spec_ext_t dotta_ext_none;
extern const dotta_spec_ext_t dotta_ext_required;
extern const dotta_spec_ext_t dotta_ext_optional_silent;
extern const dotta_spec_ext_t dotta_ext_path_only;

#endif /* DOTTA_CMD_RUNTIME_H */
