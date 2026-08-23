/**
 * runtime.h - The contract between the dispatcher and the commands it dispatches to
 *
 * Declares the run (what the dispatcher opened for one command), the dispatch
 * context (the run plus the command envelope — what every handler receives and
 * its sub-handlers carry), the needs every command spec declares, and the
 * accessor through which the cmds/ layer reaches the root registry without
 * naming its storage symbol. The dispatch *implementation* (registry array,
 * run_spec, open_run / close_run) stays file-local in main.c; this header is
 * the typed surface it exposes.
 *
 * Contents:
 *   - `dotta_state_mode_t` — the shape a command opens state in;
 *   - `dotta_needs_t`      — payload referenced by `args_command_t::payload`:
 *                            the run members a handler reads, declared in
 *                            full, without the base/args engine learning them;
 *   - `dotta_run_t`        — the run: repo, state, mounts, keymgr, cache, the
 *                            view — each NULL unless its need was declared and
 *                            its open succeeded;
 *   - `dotta_ctx_t`        — the run plus the envelope (arena, config, out,
 *                            argc / argv, exit_code), handed to each command's
 *                            dispatch handler;
 *   - `dotta_registry()`   — typed accessor for the root registry, consumed by
 *                            `cmds/completion.c` to export the fish completion
 *                            script and to answer the shell's candidates at
 *                            runtime.
 *
 * Where the context stops
 * -----------------------
 * Every API boundary is explicit; the context is the vehicle within a command.
 * A core entry point takes, by name, each resource it reads — what it takes is
 * its contract, and it checks it at its own boundary (`manifest_build`,
 * `scope_build`, `workspace_load`, `deploy_execute`, `ignore_rules_create`);
 * no core header includes this one. A command-layer function takes the context
 * when it reads two or more of its resources, and the call from cmds into core
 * is the line where the dependencies are spelled out:
 * `manifest_build(ctx->run.repo, ctx->run.state, ctx->arena, &m)`. What a
 * command built — a scope, a workspace, the view after its own mutation — is a
 * parameter, never read off the context: the context carries the dispatcher's
 * instant and nothing the command made.
 */

#ifndef DOTTA_RUNTIME_H
#define DOTTA_RUNTIME_H

#include <stdbool.h>
#include <types.h>          /* error_t, arena_t, config_t, output_t */

/* libgit2's opaque repo type. Consumers that touch the pointer must `#include
 * <git2.h>` for the API; this header stays free of the libgit2 dependency so it
 * can be included transitively without forcing every TU through git2.h. */
struct git_repository;

/* Core state handle. The full API lives in `src/core/state.h`; consumers that
 * call state functions include that header. Redeclaring the typedef here keeps
 * the contract typed without pulling core/ into every TU that reaches ctx. C11
 * §6.7p3 permits a typedef name to be redeclared to the same type, so this coexists
 * with core/state.h's identical typedef in any TU that includes both. Mirrors
 * the struct-tag forward decl above. */
typedef struct state state_t;

/* Per-machine mount-table handle. The full API lives in `src/infra/mount.h`;
 * consumers that call mount functions include that header. Same C11 §6.7p3
 * typedef-redeclaration rationale as state_t above. */
typedef struct mount_table mount_table_t;

/* Crypto handles. Full APIs in `crypto/keymgr.h` and `infra/content.h`; TUs that
 * call their functions include those headers. */
typedef struct keymgr keymgr;
typedef struct content_cache content_cache_t;

/* The view. Full API in `src/core/manifest.h`; consumers that read rows include
 * that header. Same C11 §6.7p3 typedef-redeclaration rationale as state_t. */
typedef struct manifest manifest_t;

/* Spec-engine command descriptor. Forward-declared (rather than pulling
 * `base/args.h`) so that every TU that transitively includes `runtime.h` does
 * not drag the full `args_command_t` definition through its compile. Same rationale
 * as the `struct git_repository` forward decl above, and the pattern
 * `include/types.h` uses for `error_t` / `arena_t`. */
typedef struct args_command args_command_t;

/**
 * The shape a command opens state in
 *
 * READ is `state_load`: a command that declares it may still take scoped write
 * transactions via `state_begin` / `state_commit` on the borrowed handle —
 * update, revert, remove. WRITE is `state_open`: `BEGIN IMMEDIATE` held for the
 * lifetime of dispatch, and the command calls `state_save` when its mutation is
 * complete; `state_free` in the dispatcher rolls back any uncommitted
 * transaction.
 *
 * CREATE-style commands (init, clone) declare NONE and open state themselves,
 * because the database file does not exist before dispatch runs — there is
 * nothing for the dispatcher to acquire. This parallels their undeclared
 * `repo`: both resources are self-owned during creation.
 */
typedef enum dotta_state_mode {
    DOTTA_STATE_NONE,   /* No state handle */
    DOTTA_STATE_READ,   /* state_load; scoped writes via state_begin/state_commit */
    DOTTA_STATE_WRITE   /* state_open (BEGIN IMMEDIATE); the command calls state_save */
} dotta_state_mode_t;

/**
 * The needs — every run member a command's handler reads
 *
 * Pointed at by `args_command_t::payload`, in place on the spec:
 *
 *     .payload = &(const dotta_needs_t){ .repo = true, .state = DOTTA_STATE_READ },
 *
 * a file-scope compound literal — static storage, its address an address
 * constant (C11 §6.5.2.5p5, §6.6p9). A spec without a payload opens nothing
 * (init, clone, completion). Additional fields (privilege escalation, verbosity
 * override, …) land here as new members without touching the engine — this is
 * the extension point `main.c::run_spec` reads.
 *
 * The spec names the full set, not the deepest need on each chain: a reader
 * learns that `status` reads the state from `status`'s spec, not from a
 * lattice. The dispatcher refuses a set that is not closed under the
 * dependencies — `state ⇒ repo`, `crypto ⇒ repo`, `mounts ⇒ state`,
 * `manifest ⇒ state` — before it opens anything, so an incoherent spec fails
 * its command's first run. A member the handler reads without declaring is
 * NULL, and fails at the first core boundary that checks it, naming the
 * parameter.
 *
 * repo
 * ----
 * `repo_open`: the handle and its path. A command that only forks a child over
 * the repository (git) holds the handle while the child runs — libgit2 takes no
 * lock on open, and nothing the child writes is read back afterwards.
 *
 * state
 * -----
 * The handle in the declared shape (`dotta_state_mode_t`). Requires `repo`.
 *
 * mounts
 * ------
 * This machine's topology over the enabled set — `profile_build_mount_table`
 * over the state's rows and `$HOME` — for classifying the command's input
 * (`path_input_resolve`, `scope_build`). Requires `state`. A command that reads
 * a CLI path declares it; the view does not need it — the builder derives its
 * own table from the rows it reads.
 *
 * crypto
 * ------
 * The content cache always, the keymgr iff `config->encryption_enabled`.
 * Requires `repo`. Both handles are borrowed by the handler; the dispatcher
 * tears them down LIFO (cache, then keymgr) before state teardown.
 *
 * Why no split between "key only" and "key + cache": the codebase has exactly
 * one cache primitive (`infra/content`'s blob-OID → plaintext map). With one
 * cache, the dispatcher carries no information by distinguishing "needs keymgr"
 * from "needs keymgr and cache" — it would just be a hint about whether the
 * handler iterates blobs in batch. Single-blob handlers (`add`, `show`,
 * `revert`, `key`) tolerate an unused empty cache (one calloc plus a 64-entry
 * hashmap, freed in LIFO teardown) in exchange for a uniform handle shape
 * across every crypto-aware command. If a second cache primitive ever lands,
 * this rationale is the place to revisit the split.
 *
 * Disabled-encryption semantics: when `config->encryption_enabled == false`,
 * `run.keymgr` stays NULL regardless of the need; the cache is still created
 * with a NULL keymgr so callers deal with one shape. Handlers forward
 * `run.keymgr` to the content layer unconditionally — it surfaces ERR_CRYPTO
 * with a user-facing message naming the file if a per-file operation asks to
 * encrypt or decrypt without a key, so commands never need to gate on "do I
 * have a key?" before calling through.
 *
 * manifest
 * --------
 * The view — every enabled profile at HEAD, precedence resolved, one row per
 * managed path (`core/manifest.h`) — `manifest_build` over the state's enabled
 * set. Requires `state`. Borrowed by the handler, released by the dispatcher.
 *
 * Who declares it: the commands whose subject is the view — the workspace
 * commands (status, diff, apply, sync, update — `workspace_load` borrows the
 * view rather than building one), `remove` (who owned a path a moment before
 * the commit is read off the view before it) and `profile enable` (its receipt
 * is the diff between the view before and the view after). A build that fails
 * ends dispatch with the builder's message — a tree that will not load, a
 * custom/ path under a profile with no target — on every path of the command,
 * including the ones that would not have read the view; the enabled set is
 * broken as a whole, and `profile disable` is the way out.
 *
 * Who does not: a command for which the view is incidental (one lookup or one
 * count on one of its paths — `show`, `list`, `key status`, `completion`) or
 * that must run on a set the build refuses (`profile disable`) builds its own
 * with `manifest_build` where it needs it, with the failure handling that path
 * wants. A command that moves Git or the enabled set (add, update, remove,
 * sync, profile enable / disable, clone, interactive) builds the post-mutation
 * view itself — the builder called again over the rows as they now stand:
 * `run.manifest` is the view at dispatch and is never rebuilt — see "Members
 * not welcome" #1 on the run.
 *
 * tolerant
 * --------
 * The dispatcher opens what the command cannot run without; a failed open ends
 * the command with the resource's own message, before any effect. What a
 * command *can* run without, it builds where it needs it, with the context in
 * hand, and handles the failure the way that path wants. `tolerant` is the one
 * whole-run exception, for a command whose contract is silence: completion
 * must run its hook wherever it is invoked — outside a repository every source
 * prints nothing and the shell falls back to native paths — so its run opens
 * tolerantly. The first open that fails ends the open: what opened stays, the
 * rest is NULL, the error is dropped, and the handler runs. A source may then
 * see `repo` without `state` (a database that will not load) and returns on
 * the first NULL it reads.
 */
typedef struct dotta_needs {
    bool repo;                  /* The repository handle and its path */
    dotta_state_mode_t state;   /* NONE, READ or WRITE. Requires repo */
    bool mounts;                /* This machine's topology over the enabled set. Requires state */
    bool crypto;                /* The content cache, and the keymgr iff encryption is on. Requires repo */
    bool manifest;              /* The view at dispatch. Requires state */
    bool tolerant;              /* Open what opens; a failure ends the open without error */
} dotta_needs_t;

/**
 * The run — what the dispatcher opened for this command
 *
 * One rule: a member is non-NULL iff its need was declared and its open
 * succeeded — a fixed shape, read the same way by every consumer. `open_run`
 * populates the members in place, in dependency order, before the handler
 * runs; `close_run` releases them in LIFO after it returns; in between every
 * member is borrowed. Handlers read them as `ctx->run.x` and name them, one by
 * one, at every call into core; commands never free a member.
 *
 *   - `repo_path` is non-NULL iff `repo` is. `repo_open` already resolves the
 *     path to open the repo; threading it out costs nothing and gives commands
 *     that need both (bootstrap, which exports DOTTA_REPO_DIR to child scripts;
 *     git, which forks the child over it) a single source of truth instead of
 *     a second `resolve_repo_path` call. An arena copy: the run holds only
 *     borrowed or arena-owned strings, and `close_run` frees no `const char *`.
 *   - `state` is the handle in the declared shape; dispatch closes it on
 *     return (`state_free` rolls back any uncommitted transaction).
 *   - `mounts` is a value: built into the command arena from the state's rows
 *     and `$HOME`, it borrows nothing from the row cache, so after a command
 *     mutates the binding set (profile enable/disable, clone, interactive,
 *     add-with-implicit-enable) it still reads as the topology at dispatch —
 *     the one before. It classifies the command's input; the view derives its
 *     own table from the rows it reads.
 *   - `keymgr != NULL` implies `config->encryption_enabled`. `content_cache`
 *     carries a borrowed pointer to it (NULL when encryption is disabled) and
 *     is torn down before it.
 *   - `manifest` is the view over the enabled set as it stands at dispatch —
 *     its rows in the command arena, its index released by the dispatcher after
 *     the handler returns. Never reassigned: a command that moves Git (a commit,
 *     a pull) or the enabled set builds the post-mutation view itself and frees
 *     it itself, and `run.manifest` stays the view before — which is exactly
 *     what the receipts diff against (`manifest_diff(ctx->run.manifest, after,
 *     …)`).
 *
 * Owning-typed pointers where `close_run` frees (`manifest_t *`,
 * `content_cache_t *`, `keymgr *`, `state_t *`, `git_repository *`); `const`
 * where nothing does (`mounts` and `repo_path` are the arena's). Below the
 * dispatcher the contract is `const dotta_ctx_t *`: the pointers are
 * `T *const`, the pointees live — state takes transactions, the cache fills.
 *
 * Members not welcome on this struct
 * ----------------------------------
 * The following patterns have been rejected by the design and must not be added
 * without first re-evaluating the whole ownership model:
 *
 *   1. No invalidation API on the run for any field. Command-scoped resources
 *      do not need invalidation; a need to "clear" a resource mid-command is an
 *      API operation on the borrowed handle (e.g. `keymgr_clear(ctx->run.keymgr)`
 *      inside `dotta key clear`), not a run-layer concern. The derived members
 *      are snapshots: the second instant is the builder called again.
 *   2. No lazy accessors (`run_get_X(run)` that construct on first call).
 *      Fields are populated eagerly by dispatch before the handler runs, so
 *      handlers see a fixed shape.
 *   3. No "reach inside workspace to borrow its resource" pattern. Resources
 *      that multiple dispatch steps share live on the run; there is never a
 *      `workspace_get_X` / `state_get_X` accessor that exposes run-scope
 *      resources via a lower layer. The workspace's products (rows, records,
 *      verdicts) are read through the workspace; the run's resources are read
 *      through the context, at every layer.
 */
typedef struct dotta_run {
    struct git_repository *repo;        /* needs->repo */
    const char *repo_path;              /* Non-NULL iff repo; an arena copy */
    state_t *state;                     /* needs->state != NONE; the READ or WRITE shape */
    const mount_table_t *mounts;        /* needs->mounts; this machine's topology at dispatch */
    keymgr *keymgr;                     /* needs->crypto, and only if encryption is on */
    content_cache_t *content_cache;     /* needs->crypto */
    manifest_t *manifest;               /* needs->manifest; the view at dispatch */
} dotta_run_t;

/**
 * The dispatch context — the run plus the command envelope
 *
 * Populated by the dispatcher, read by each command's handler and by the
 * sub-handlers it passes itself to. The run is a member by value: one object,
 * opened in place before dispatch and closed in place after it, no second
 * pointer to keep coherent. The envelope is what the dispatcher has without
 * opening anything — the command arena, the process's config, the output
 * context, argv, the exit-code override — and is always present.
 *
 * Bundling is deliberate, and bounded. Within a command the context is the
 * vehicle: a sub-handler that reads two or more of its resources takes it
 * whole and opens with one alias per run member it reads, so the members that
 * depend on the spec stand in one place a reader can match against it. Core
 * never takes it: a core entry point takes its inputs by name, and the call
 * into core is where the bundle is unpacked. A future resource lands here as a
 * member and a need, not as signature churn across every command.
 *
 * Arena lifetimes
 * ---------------
 * The codebase has exactly two arena lifetimes:
 *
 *   - Process-scope. `config->auto_encrypt.arena` holds the compiled auto-encrypt
 *     ruleset, allocated once at config_load and read-only thereafter. Lives
 *     the whole process; outlives every dispatch.
 *
 *   - Command-scope. `ctx->arena` is the dispatch-wide bump allocator, created
 *     and destroyed by `run_spec`. Handlers allocate into it directly or thread
 *     it as an `arena_t *` parameter; the parser uses the same arena since its
 *     outputs are read by the handler, and every derived member of the run (the
 *     mount table, the view's rows) lives in it. Handlers and every layer
 *     beneath borrow the pointer — never call `arena_destroy(ctx->arena)`.
 *
 * Adding a third arena requires evidence of a genuinely sub-command lifetime in
 * code — an interactive REPL with per-iteration scope, for example. Hypothesised
 * need is not enough; a primitive exists when a real consumer exists.
 * Single-threaded by design (no pthread, no async I/O loop), so concurrent
 * allocation is not a concern.
 *
 * Exit-code override
 * ------------------
 * Dispatch returns `error_t *` — dotta's native failure channel. For native
 * commands a non-NULL error collapses to process exit `1` and a NULL error
 * collapses to `0`; the single bit is enough.
 *
 * Pass-through commands (e.g. `dotta git`) run an external tool whose *exact*
 * exit status is the contract users rely on (`git diff --exit-code` returns 1
 * on diffs, 128+n on signals, etc.). They assign `*ctx->exit_code` to the value
 * they want dotta to exit with and return `NULL` from dispatch. Main honors that
 * value when no error is reported; otherwise the error path wins.
 *
 * The runner owns the int: `run_spec` allocates it on its frame, initializes it
 * to 0, and points `exit_code` at it. This keeps `ctx` const-honest — the struct's
 * pointer field never mutates, only the pointee does, which was never const.
 * Native commands that never touch the pointer leave the runner at 0 and exit
 * cleanly.
 */
typedef struct dotta_ctx {
    dotta_run_t run;                    /* By value: opened and closed in place by run_spec */
    arena_t *arena;                     /* Command-scoped; created before the parse, destroyed after the close */
    const config_t *config;             /* Process-scoped, borrowed */
    output_t *out;
    int argc;                           /* Original process argc */
    char **argv;                        /* Original process argv */
    int *exit_code;                     /* Non-NULL; *exit_code overrides exit when err==NULL */
} dotta_ctx_t;

/**
 * Accessor for the root command registry.
 *
 * Returns the NULL-terminated `args_command_t *const []` defined as `static`
 * data in main.c. The pointer is borrowed; never freed by the caller. Only
 * consumer today is `cmds/completion.c`: it projects the registry into the
 * fish-completion script (`make completions`) and resolves the shell's command
 * line against it when asked for candidates.
 *
 * The accessor exists so the cmds/ layer can read the registry without
 * compile-depending on the registry symbol itself — the storage stays file-local
 * in main.c, and this function is its typed public face.
 */
const struct args_command *const *dotta_registry(void);

#endif /* DOTTA_RUNTIME_H */
