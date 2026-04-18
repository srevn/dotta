/**
 * runtime.h - Cross-layer contract between main.c and the cmds/ layer
 *
 * Declares the types every command handler reads, the payloads every
 * command spec declares, and the accessor through which the cmds/ layer
 * reaches the root registry without naming its storage symbol. The
 * dispatch *implementation* (registry array, run_spec, repo-acquisition
 * helpers) stays file-local in main.c; this header is the typed surface
 * it exposes.
 *
 * Contents:
 *   - `dotta_repo_mode_t` — repo-open contract honored by the dispatcher;
 *   - `dotta_spec_ext_t`  — payload referenced by `args_command_t::payload`,
 *                           letting each command declare its repo mode in
 *                           a typed way without the base/args engine
 *                           learning the enum;
 *   - `dotta_ctx_t`       — bundle handed to each command's dispatch
 *                           handler (repo, config, output, arena, ...);
 *   - `dotta_ext_*`       — one per repo mode; commands point
 *                           `payload` at the constant matching their need;
 *   - `dotta_registry()`  — typed accessor for the root registry,
 *                           consumed by `cmds/completion.c` when exporting
 *                           the fish completion script.
 */

#ifndef DOTTA_RUNTIME_H
#define DOTTA_RUNTIME_H

#include <types.h>          /* error_t, arena_t, config_t, output_ctx_t */

/* libgit2's opaque repo type. Consumers that touch the pointer must
 * `#include <git2.h>` for the API; this header stays free of the
 * libgit2 dependency so it can be included transitively without
 * forcing every TU through git2.h. */
struct git_repository;

/* Spec-engine command descriptor. Forward-declared (rather than pulling
 * `base/args.h`) so that every TU that transitively includes
 * `runtime.h` does not drag the full `args_command_t` definition
 * through its compile. Same rationale as the `struct git_repository`
 * forward decl above, and the pattern `include/types.h` uses for
 * `error_t` / `arena_t`.
 *
 * The `args_command_t` alias is provided here so consumers that only
 * need to declare `extern const args_command_t spec_foo;` can work off
 * `<runtime.h>` alone. The full struct definition still lives in
 * `base/args.h`; files that need to access members or initialize a
 * `spec_foo` literal include that header directly. The typedef is
 * redeclared (not re-defined) — C11 §6.7p3 permits identical typedef
 * redeclarations, so both this header and `base/args.h` may coexist. */
typedef struct args_command args_command_t;

/**
 * Repository-opening contract honored by the dispatcher.
 *
 * Each command declares its repo needs via a `dotta_spec_ext_t` payload
 * pointed at by `args_command_t::payload`. Main.c reads the mode in
 * `run_spec` and opens the repo (or not) accordingly before dispatch.
 */
typedef enum dotta_repo_mode {
    DOTTA_REPO_NONE,            /* No repo handle needed */
    DOTTA_REPO_REQUIRED,        /* Error if repo_open fails; sets repo + repo_path */
    DOTTA_REPO_OPTIONAL_SILENT, /* NULL on failure; no error reported */
    DOTTA_REPO_PATH_ONLY        /* Resolve path, hand it via ctx->repo_path */
} dotta_repo_mode_t;

/**
 * Per-command extension payload referenced by `args_command_t::payload`.
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
 *   `repo`/`repo_path`/`arena`  — command-scoped (created in
 *                                 run_spec, destroyed on return).
 *   `config`/`out`              — process-scoped (created in main).
 *   `argc`/`argv`               — process-scoped (kernel-supplied).
 *   `exit_code`                 — points to a stack int in run_spec;
 *                                 command-scoped lifetime.
 *
 * Invariant: whenever `repo` is non-NULL, `repo_path` is non-NULL too.
 * `repo_open` already resolves the path to open the repo; threading it
 * out costs nothing and gives commands that need both (e.g. bootstrap,
 * which exports DOTTA_REPO_DIR to child scripts) a single source of
 * truth instead of a second `resolve_repo_path` call.
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
    const char *repo_path;              /* Set by REQUIRED and PATH_ONLY modes */
    const config_t *config;
    output_ctx_t *out;
    arena_t *arena;                     /* Command-scoped; parser-owned */
    int argc;                           /* Original process argc */
    char **argv;                        /* Original process argv */
    int *exit_code;                     /* Non-NULL; *exit_code overrides exit when err==NULL */
} dotta_ctx_t;

/* Per-mode payloads. Each command's spec sets `.payload = &dotta_ext_X`
 * for the matching mode; main.c reads it back in run_spec. The four
 * constants are defined in main.c beside the dispatcher that consumes
 * them — referenced from every command file but defined exactly once. */
extern const dotta_spec_ext_t dotta_ext_none;
extern const dotta_spec_ext_t dotta_ext_required;
extern const dotta_spec_ext_t dotta_ext_optional_silent;
extern const dotta_spec_ext_t dotta_ext_path_only;

/**
 * Accessor for the root command registry.
 *
 * Returns the NULL-terminated `args_command_t *const []` defined as
 * `static` data in main.c. The pointer is borrowed; never freed by
 * the caller. Only consumer today is `cmds/completion.c`, which
 * projects the registry into the fish-completion dialect when the
 * build emits `etc/completions/dotta-completions.fish`.
 *
 * The accessor exists so the cmds/ layer can read the registry
 * without compile-depending on the registry symbol itself — the
 * storage stays file-local in main.c, and this function is its
 * typed public face.
 */
const struct args_command *const *dotta_registry(void);

#endif /* DOTTA_RUNTIME_H */
