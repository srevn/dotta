/**
 * runtime.h - The contract between the dispatcher and the commands it dispatches to
 *
 * Declares the run (what the dispatcher opened for one command), the dispatch
 * context (the run plus the command envelope — what every handler receives and
 * its sub-handlers carry), the needs every command spec declares, and the accessor
 * through which the cmds/ layer reaches the root registry without naming its
 * storage symbol. The dispatch *implementation* (registry array, run_spec, open_run
 * / close_run) stays file-local in main.c; this header is the typed surface it
 * exposes.
 *
 * Contents:
 *   - `dotta_state_mode_t` — the shape a command opens state in;
 *   - `dotta_crypto_mode_t` — how far the keymgr may reach for a passphrase;
 *   - `dotta_verbosity_t`  — what a spec's -v or -q asked of the run's level;
 *   - `dotta_needs_t`      — payload referenced by `args_command_t::payload`:
 *                            the run members a handler reads, declared in full,
 *                            without the base/args engine learning them;
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
 * `manifest_build(ctx->run.repo, ctx->run.state, ctx->arena, &m)`. What a command
 * built — a scope, a workspace, the view after its own mutation — is a parameter,
 * never read off the context: the context carries the dispatcher's instant and
 * nothing the command made.
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
 * Whether a command opens the repository
 *
 * OPEN is `repo_open`: the libgit2 handle over the store's directory the
 * configuration settled (`config->repo_dir`, which every command reads there
 * whether it opens or not). CREATE-style commands (init, clone) declare NONE
 * and open the repository themselves, because it does not exist before dispatch
 * runs; the pass-through (git) declares NONE and opens nothing, because it forks
 * the real git over the directory (cmds/git.h says why it must not open).
 */
typedef enum dotta_repo_mode {
    DOTTA_REPO_NONE,   /* No repository member */
    DOTTA_REPO_OPEN    /* repo_open: the handle over the settled directory */
} dotta_repo_mode_t;

/**
 * The shape a command opens state in
 *
 * READ is `state_load`: a command that declares it may still take scoped write
 * transactions via `state_begin` / `state_commit` on the borrowed handle — update,
 * revert, remove. WRITE is `state_open`, which is `state_load` promoted by
 * `state_begin` at dispatch: `BEGIN IMMEDIATE` held for the lifetime of dispatch,
 * and the command calls `state_save` when its mutation is complete — or at a
 * boundary inside it, taking the lock back with `state_resume` for what remains,
 * which refuses where another process wrote in between (apply's checkpoint,
 * core/state.h); `state_free` in the dispatcher rolls back any uncommitted
 * transaction.
 *
 * The dispatcher's rollback comes after everything the command does, so a WRITE
 * command that runs anything more once its mutation is over — a hook, a subprocess,
 * any other reader of the store — finishes the transaction itself first, saved
 * or rolled back, rather than leaving a lock nothing will use again (`cmds/apply`
 * commits before its post hook; `cmds/add`'s record phase rolls back at its one
 * exit). The lock is held from before `hook_fire_pre` as well, which is deliberate
 * — two applies must not interleave — and is why a hook of a WRITE command cannot
 * itself run a `dotta` command that needs the write lock (etc/hooks/README.md).
 *
 * A preview of a WRITE command opens READ. The dispatcher asks the spec's own
 * `--dry-run` row before the first open and narrows the mode when this invocation
 * set it (`main.c::open_run`), so nothing below acquisition ever meets a fourth
 * word — every consumer reads a handle in one of the three shapes and never asks
 * how it was decided. A writing command with no preview (`profile reorder`) carries
 * no such row, answers NULL and keeps its shape; nothing is declared anywhere,
 * and a spec that grows a `--dry-run` gets the rule by growing it.
 *
 * The rule is that a preview holds nothing, not that it writes nothing. What
 * skips a mutation is the command's own preview branch, and READ permits a scoped
 * `state_begin` by contract — so a command that writes at a moment rather than
 * across its dispatch declares READ and promotes there (`profile validate --fix`,
 * update, remove, revert), and a preview that records what it read does so through
 * the same scoped transaction status and diff use (the workspace flush,
 * `core/workspace.h`): an observation is a reading, and the next load would have
 * to establish it again.
 *
 * CREATE-style commands (init, clone) declare NONE and open state themselves,
 * because the database file does not exist before dispatch runs — there is nothing
 * for the dispatcher to acquire. This parallels their undeclared `repo`: both
 * resources are self-owned during creation.
 */
typedef enum dotta_state_mode {
    DOTTA_STATE_NONE,    /* No state handle */
    DOTTA_STATE_READ,    /* state_load; scoped writes via state_begin/state_commit */
    DOTTA_STATE_WRITE    /* state_open (BEGIN IMMEDIATE); the command calls state_save */
} dotta_state_mode_t;

/**
 * How far the keymgr may reach for a passphrase
 *
 * The caches — what earlier runs left — or the user. CACHED never asks: a command
 * that reports declares it, and an encrypted row it cannot open with what is
 * cached reads as unverifiable (ERR_LOCKED at the look) rather than the report
 * stopping at a prompt. OBTAIN may read DOTTA_ENCRYPTION_PASSPHRASE and prompt:
 * a command the user asked to do something with the content declares it. NONE
 * is no crypto member at all. The words are `keymgr_reach_t`'s (crypto/keymgr.h),
 * plus NONE.
 */
typedef enum dotta_crypto_mode {
    DOTTA_CRYPTO_NONE,     /* No crypto members */
    DOTTA_CRYPTO_CACHED,   /* The keymgr reads the caches and never asks */
    DOTTA_CRYPTO_OBTAIN    /* … and may read the environment and prompt */
} dotta_crypto_mode_t;

/**
 * What -v or -q asked of the run's verbosity
 *
 * A spec that takes either declares them as one ARGS_FLAG_SET group on an int
 * named `verbosity` (base/args.h, "Tri-state flags"), so the pair is a
 * contradiction the parse refuses as it refuses every other, and a spec that
 * grows a -v gets the rule by growing it. The dispatcher reads the group off
 * the spec's own rows before the run opens (main.c run_spec), as open_run reads
 * --dry-run, and sets the output's level over the configuration's; no handler
 * sets one. A handler reads the field only where the flag says more than a level:
 * clone's -q declines its bootstrap prompt too (cmds/clone.c cmd_clone). The
 * words are output_verbosity_t's (base/output.h), plus DEFAULT.
 */
typedef enum dotta_verbosity {
    DOTTA_VERBOSITY_DEFAULT = 0,   /* Neither: the configuration's level stands */
    DOTTA_VERBOSITY_QUIET,         /* -q */
    DOTTA_VERBOSITY_VERBOSE        /* -v */
} dotta_verbosity_t;

/**
 * The needs — every run member a command's handler reads
 *
 * Pointed at by `args_command_t::payload`, in place on the spec:
 *
 *     .payload = &(const dotta_needs_t){ .repo = DOTTA_REPO_OPEN, .state =
 *     DOTTA_STATE_READ },
 *
 * a file-scope compound literal — static storage, its address an address constant
 * (C11 §6.5.2.5p5, §6.6p9). A spec without a payload opens nothing (init, clone,
 * completion). Additional fields land here as new members without touching the
 * engine — this is the extension point `main.c::open_run` reads. Privilege is
 * not one of them and never will be: the identity of the run is a process fact
 * (sys/identity), and what a run cannot do as the invoker is each engine's
 * preflight skip, not a need. Nor is what an invocation asks of the run, which
 * the dispatcher reads off the spec's own rows (--dry-run, dotta_verbosity_t).
 *
 * The spec names the full set, not the deepest need on each chain: a reader learns
 * that `status` reads the state from `status`'s spec, not from a lattice. The
 * dispatcher refuses a set that is not closed under the dependencies — `state ⇒
 * repo`, `crypto ⇒ repo`, `mounts ⇒ state`, `manifest ⇒ state` — before it opens
 * anything, so an incoherent spec fails its command's first run. A member the
 * handler reads without declaring is NULL, and fails at the first core boundary
 * that checks it, naming the parameter.
 *
 * repo
 * ----
 * The repository in the declared shape (`dotta_repo_mode_t`): the handle repo_open
 * made over the store's directory the configuration settled, or none. A command
 * that wants the directory and not the handle reads the configuration
 * (`config->repo_dir`), as the pass-through does (cmds/git.h).
 *
 * state
 * -----
 * The handle in the declared shape (`dotta_state_mode_t`). Requires `repo` at
 * OPEN — state lives in the repository dotta opened. A WRITE spec whose `--dry-run`
 * flag this invocation set opens READ instead. The closure above is tested against
 * what the spec declares: narrowing yields READ and never NONE, so nothing it
 * checks can come out differently for a preview.
 *
 * mounts
 * ------
 * This machine's topology over the enabled set — `manifest_mount_table` over
 * the state's rows and `$HOME` — for placing a storage path the command reads
 * (`mount_resolve`). Naming a path beneath its roots is the view's own over the
 * table it lends and no verb here (`core/manifest.h` `manifest_name`). Requires
 * `state`. A command declares it when it asks one of the table's verbs: where a
 * claim stands (`mount_resolve`: diff, ignore, remove, revert, update), a view
 * of one branch placed by it (`manifest_build_branch`: diff, export, ignore,
 * list, remove, revert, show), or a claim's ancestors climbed
 * (`metadata_capture_ancestors`: update). Reading a CLI path is not one of those
 * verbs: an argument's key is the normalizer's own string and no root's spelling
 * is read to make it (`infra/path.h`), so apply, whose path filter is those
 * strings, and status and sync, which filter by profile alone and compile none,
 * declare no table. add asks the verbs and declares none: it brings a binding
 * no row need hold (`add --target`) and builds the same table with that binding
 * standing for its profile's row (`core/manifest.h` `manifest_mount_table`),
 * where the dispatcher's would be a second build of the same rows. A command
 * that declares the view as well borrows the view's table — `manifest_mounts`,
 * the one the builder derived from the rows it read — so the names it places
 * and the rows it selects read one value; a command that declares `mounts` alone
 * gets its own build from the same rows. Every filesystem path the run spells —
 * a row's, a record's, an argument's — is a root's spelling and a tail, the
 * binder's or the user's own (`infra/mount.h`).
 *
 * crypto
 * ------
 * The content cache always, the keymgr iff `config->encryption_enabled`, at the
 * declared strength (`dotta_crypto_mode_t`): how far the keymgr may reach for a
 * passphrase. CACHED reads what earlier runs left — the session file — and never
 * asks: it never prompts, never reads DOTTA_ENCRYPTION_PASSPHRASE, never writes
 * the file. The commands that report declare it (status, sync, key status, key
 * clear), so a look at an encrypted row with cold caches fails as ERR_LOCKED
 * and the row reads as unverifiable. OBTAIN may read the environment and prompt;
 * the commands the user asked to do something with the content declare it (add,
 * update, apply, diff, show, export, revert, key set). A fresh master an OBTAIN
 * run derives is verified against the repository's own ciphertext before it is
 * kept — the keymgr finds one through the witness source it is created with
 * (`epoch_find_ciphertext`) — and `key set` is the verb that verifies against
 * the repository rather than against what an earlier run left. Requires `repo`.
 * Both handles are borrowed by the handler; the dispatcher tears them down LIFO
 * (cache, then keymgr) before state teardown.
 *
 * Why no split between "key only" and "key + cache": the codebase has exactly
 * one cache primitive (`infra/content`'s blob-OID → plaintext map). With one
 * cache, the dispatcher carries no information by distinguishing "needs keymgr"
 * from "needs keymgr and cache" — it would just be a hint about whether the handler
 * iterates blobs in batch. Single-blob handlers (`add`, `show`, `revert`, `key`)
 * tolerate an unused empty cache (one calloc freed in LIFO teardown, and a 64-entry
 * map in the command arena) in exchange for a uniform handle shape across every
 * crypto-aware command. If a second cache primitive ever lands, this rationale
 * is the place to revisit the split.
 *
 * Disabled-encryption semantics: when `config->encryption_enabled == false`,
 * `run.keymgr` stays NULL regardless of the need; the cache is still created
 * with a NULL keymgr so callers deal with one shape. Handlers forward `run.keymgr`
 * to the content layer unconditionally — it refuses with a message naming the
 * file if a per-file operation asks to encrypt or decrypt without a keymgr (both
 * ERR_LOCKED: no key in reach), so a command never gates on the key itself: it
 * calls through, or asks `content_require_encryption` ahead of a capture it has
 * not begun (`cmds/add`'s decision pass).
 *
 * manifest
 * --------
 * The view — every enabled profile at HEAD, precedence resolved, one row per
 * active path (`core/manifest.h`) — `manifest_build` over the state's enabled
 * set. Requires `state`. Borrowed by the handler, and a value of the command
 * arena, which nothing frees (the run, below).
 *
 * Who declares it: the commands whose subject is the view — the workspace commands
 * (status, diff, apply, sync, update — `workspace_load` borrows the view rather
 * than building one) and `profile enable` (its receipt is the diff between the
 * view before and the view after). A build that fails ends dispatch with the
 * builder's message — a tree that will not load, metadata that will not parse —
 * on every path of the command, including the ones that would not have read the
 * view; such a set is broken as a whole, and `profile disable` (or `remove`) is
 * the way out. A custom/ claim under a profile with no target is not such a
 * failure: the build is total over it — no row, recorded on the view
 * (`manifest_unbound`) — and the health consumers (status, apply, sync) surface
 * the held claims.
 *
 * Who does not: a command for which the view is incidental (one lookup or one
 * count on one of its paths — `show`, `list`, `key status`, `completion`, `export`
 * and `ignore --test`, the last two reading one branch's own view where the enabled
 * set is not the subject, and `ignore`'s other four surfaces building
 * nothing) or that must run on a set the build refuses (`profile disable`;
 * `remove` — its warning bit and its record phase each build a view where needed
 * and degrade when the build fails) builds its own where it needs it, with the
 * failure handling that path wants. A command that moves Git or the enabled set
 * (add, update, remove, sync, profile enable / disable, clone, interactive) builds
 * the post-mutation view itself — the builder called again over the rows as they
 * now stand: `run.manifest` is the view at dispatch and is never rebuilt — see
 * "Members not welcome" #1 on the run.
 *
 * tolerant
 * --------
 * The dispatcher opens what the command cannot run without; a failed open ends
 * the command with the resource's own message, before any effect. What a command
 * *can* run without, it builds where it needs it, with the context in hand, and
 * handles the failure the way that path wants. `tolerant` is the one whole-run
 * exception, for a command whose contract is silence: completion must run its
 * hook wherever it is invoked — outside a repository every source prints nothing
 * and the shell falls back to native paths — so its run opens tolerantly. The
 * first open that fails ends the open: what opened stays, the rest is NULL, the
 * error is dropped, and the handler runs. A source may then see `repo` without
 * `state` (a database that will not load) and returns on the first NULL it reads.
 */
typedef struct dotta_needs {
    dotta_repo_mode_t repo;     /* NONE or OPEN */
    dotta_state_mode_t state;   /* NONE, READ or WRITE. Requires repo OPEN */
    bool mounts;                /* This machine's topology over the enabled set. Requires state */
    dotta_crypto_mode_t crypto; /* NONE, CACHED or OBTAIN: the content cache */
    bool manifest;              /* The view at dispatch. Requires state */
    bool tolerant;              /* Open what opens; a failure ends the open without error */
} dotta_needs_t;

/**
 * The run — what the dispatcher opened for this command
 *
 * One rule: a member is non-NULL iff its need was declared and its open succeeded
 * — a fixed shape, read the same way by every consumer. `open_run` populates
 * the members in place, in dependency order, before the handler runs; `close_run`
 * releases them in LIFO after it returns; in between every member is borrowed.
 * Handlers read them as `ctx->run.x` and name them, one by one, at every call
 * into core; commands never free a member.
 *
 *   - `state` is the handle in the declared shape; dispatch closes it on return
 *     (`state_free` rolls back any uncommitted transaction).
 *   - `mounts` is a value: built into the command arena from the state's rows
 *     and `$HOME`, it borrows nothing from the row cache, so it neither dangles
 *     nor shifts when the rows are re-read — it is the topology at dispatch for
 *     as long as the run lasts, and a command that moves the binding set reads
 *     the one before. Where the view is declared too it is the view's own table,
 *     lent (`manifest_mounts`): one topology per run, and still the arena's.
 *   - `keymgr != NULL` implies `config->encryption_enabled`. `content_cache`
 *     carries a borrowed pointer to it (NULL when encryption is disabled) and
 *     is torn down before it.
 *   - `manifest` is the view over the enabled set as it stands at dispatch — a
 *     value of the command arena, rows and indexes alike, which nothing frees.
 *     Never reassigned: a command that moves Git (a commit, a pull) or the enabled
 *     set builds the post-mutation view itself, and `run.manifest` stays the
 *     view before — which is exactly what the receipts diff against
 *     (`manifest_diff(ctx->run.manifest, after, …)`).
 *
 * Owning-typed pointers where `close_run` frees (`content_cache_t *`, `keymgr
 * *`, `state_t *`, `git_repository *`); `const` where nothing does (`mounts`
 * and `manifest` are the arena's). Below the dispatcher the contract is `const
 * dotta_ctx_t *`: the pointers are `T *const`, the pointees live — state takes
 * transactions, the cache fills.
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
 *   2. No lazy accessors (`run_get_X(run)` that construct on first call). Fields
 *      are populated eagerly by dispatch before the handler runs, so handlers
 *      see a fixed shape.
 *   3. No "reach inside workspace to borrow its resource" pattern. Resources
 *      that multiple dispatch steps share live on the run; there is never a
 *      `workspace_get_X` / `state_get_X` accessor that exposes run-scope resources
 *      via a lower layer. The workspace's products (rows, records, verdicts)
 *      are read through the workspace; the run's resources are read through the
 *      context, at every layer. The dispatcher populating one member from another's
 *      product at open — `mounts` from `manifest_mounts` — is the run's own shape,
 *      not this pattern: the table is the view's product, and handlers read the
 *      member, never the accessor.
 *   4. No copy of the configuration. What the load settled is read where it lives
 *      (`ctx->config->repo_dir`, the store's directory); a member holding it
 *      would be a second source for one fact, and a gate — "non-NULL iff declared"
 *      — on a value no open produces.
 */
typedef struct dotta_run {
    struct git_repository *repo;        /* needs->repo == OPEN */
    state_t *state;                     /* needs->state != NONE; the READ or WRITE shape */
    const mount_table_t *mounts;        /* needs->mounts; this machine's topology at dispatch */
    keymgr *keymgr;                     /* needs->crypto != NONE, and only if encryption is on */
    content_cache_t *content_cache;     /* needs->crypto != NONE */
    const manifest_t *manifest;         /* needs->manifest; the view at dispatch */
} dotta_run_t;

/**
 * The dispatch context — the run plus the command envelope
 *
 * Populated by the dispatcher, read by each command's handler and by the
 * sub-handlers it passes itself to. The run is a member by value: one object,
 * opened in place before dispatch and closed in place after it, no second pointer
 * to keep coherent. The envelope is what the dispatcher has without opening
 * anything — the command arena, the process's config, the output context, argv,
 * the exit-code override — and is always present.
 *
 * Bundling is deliberate, and bounded. Within a command the context is the vehicle:
 * a sub-handler that reads two or more of its resources takes it whole and opens
 * with one alias per run member it reads, so the members that depend on the spec
 * stand in one place a reader can match against it. Core never takes it: a core
 * entry point takes its inputs by name, and the call into core is where the bundle
 * is unpacked. A future resource lands here as a member and a need, not as
 * signature churn across every command.
 *
 * Memory
 * ------
 * One question places every allocation: what must this outlive, and what must
 * it not?
 *
 *   - An arena, for what lives until a scope ends. Nothing in one is freed alone,
 *     and a container lives in the arena it was made in (base/array.h,
 *     base/hashmap.h). A function whose answer is memory takes the arena its
 *     answer lives in — first, or just before the out parameter it answers through
 *     (core/manifest.h manifest_build) — unless a handle it reads lends the answer
 *     from its own (core/branch.h branch_find); a callee that fills a caller's
 *     container takes none.
 *
 *       - The process's. `main`'s, made before the command's line is parsed and
 *         freed after everything, on every exit: the line as parsed — the options
 *         struct and what the parse allocated for it, read-only once the parse
 *         returns — the identity of the run (sys/identity.h) and the configuration
 *         — the struct, every value read into it and its two compiled pattern
 *         rulesets, read-only once config_load returns. The line is the process's
 *         because it is parsed before anything is established (main.c main),
 *         the command's arena among it, and its options borrow argv's tokens,
 *         which are the process's too. The errors are a second instance of it,
 *         not another lifetime: `base/error.c`'s own arena, made at the first
 *         error and never freed, because an error is made before the command's
 *         arena exists and rendered after it is gone, and base sees no composition
 *         root to be handed main's. A loop that goes on past a failure mints it
 *         once per cause and answers it again, so what the errors keep is counted
 *         by their causes (base/error.h "Lifetime").
 *
 *       - The command's. `ctx->arena`, made and freed by `run_spec`: every value
 *         a command builds — names, rows, items, records, plans, verdicts,
 *         receipts, messages — and every container that holds them, and the run's
 *         derived members (the mount table, the view's rows). Borrowed by every
 *         layer beneath and freed by none, and never marked: its containers
 *         remember it, and a return to a mark would drop what they grew.
 *
 *       - A frame's. An arena a function makes and frees itself, for one of two
 *         reasons.
 *
 *         A lifetime shorter than the command's, earned by a number. A walk keeps
 *         one scratch, made by its driver — `core/workspace.c`'s untracked walk
 *         one per scan root, `cmds/add.c`'s one per directory argument — every
 *         frame listing into it and every entry rewinding it (sys/filesystem.h
 *         fs_listing_t), because an entry that is named and then excluded is
 *         kept by nothing: 20,000 ignored files beneath one tracked directory
 *         measured 4.1 MB of peak RSS at the shape that composed names by hand,
 *         20.3 MB against `ctx->arena`, and 4.1 MB with a scratch of the walk's
 *         own, and `add -e` over 51,000 excluded entries 13.2 MB against
 *         `ctx->arena` and 7.3 MB with one; what outlives an entry is copied at
 *         the one door it leaves through (workspace_add_untracked, add_list). A
 *         view built to read one answer off it is built in one too:
 *         `cmds/interactive.c`'s plan_check learns only that the saved set's
 *         view builds, where a session kept one per save — 50 saves over a
 *         5,000-file profile measured 120.7 MB of peak RSS against the command
 *         arena, and 46.2 MB with the check's own, 391 KB live at the end of 2
 *         saves or 50.
 *
 *         No arena in reach: a function whose answer is not memory keeps what
 *         it builds and drops within the call in a frame of its own — a spawn's
 *         environment (`utils/hooks.c` hook_execute, `utils/bootstrap.c` run_live),
 *         a run's own lists (`utils/bootstrap.c` bootstrap_fire), a fetch's
 *         refspecs (`sys/gitops.c` gitops_fetch_branches), a diff's attribution
 *         index (`core/manifest.c` manifest_diff), the table with no binding a
 *         branch's need of a target is asked of (`core/profiles.c`
 *         profile_needs_target), a listing read to decide (`sys/filesystem.c`
 *         fs_remove_empty_dir, `sys/upstream.c` upstream_ensure_tracking_branch,
 *         `infra/epoch.c` epoch_walk), a printer's sections (`cmds/status.c`
 *         status_print_workspace), and a walk whose answer is an error
 *         (`sys/filesystem.c` fs_remove_dir).
 *
 *       - A handle's own. Made by its opener and freed by its closer: the sheet
 *         (core/metadata.h), a printer's list (base/output.h output_list_t), a
 *         branch's answers (core/branch.h branch_find).
 *
 *   - The heap, for what dies before any scope does: a payload sized by its data
 *     (base/buffer.h — a file's bytes, a blob's, a diff's text), freed with the
 *     item that holds it; a handle's own struct, released by its closer; a
 *     transient built and freed within one call (heap_str_format, deploy's per-row
 *     path scratch).
 *
 *   - The library, for what a library allocates: libgit2's objects and SQLite's
 *     statements, released by the library's own verb on every path.
 *
 *   - A secure mapping, for a secret that outlives a call (base/secure.h
 *     secure_alloc); a wipe for one that does not (secure_wipe).
 *
 * Every allocation dotta makes — its own code, and cJSON's and tomlc17's through
 * the hooks main installs — succeeds or the process dies (`base/heap.h`,
 * `base/arena.h`). A mapping sized by someone else's claim (`base/secure.h`), a
 * linked library's exhaustion and a bound the design chose (`sys/filesystem.c
 * FS_MAX_READ_SIZE`, `sys/process.h PROCESS_CAPTURE_MAX`) are refusals. A new
 * scope needs the evidence one has: a genuinely shorter lifetime in code, and a
 * number — a hypothesised need is not enough. Single-threaded by design (no
 * pthread, no async I/O loop), so concurrent allocation is not a concern.
 *
 * Exit-code override
 * ------------------
 * Dispatch returns `error_t` — dotta's native failure channel. For native commands
 * a non-NULL error collapses to process exit `1` and a NULL error collapses to
 * `0`; the single bit is enough.
 *
 * Pass-through commands (e.g. `dotta git`) run an external tool whose *exact*
 * exit status is the contract users rely on (`git diff --exit-code` returns 1
 * on diffs, 128+n on signals, etc.). They assign `*ctx->exit_code` to the value
 * they want dotta to exit with. An error is told either way, and the run exits
 * with the value the dispatch set, or 1 where it set none: a passthrough that
 * could not run its tool returns the refusal beside a shell's status for it.
 *
 * The runner owns the int: `run_spec` allocates it on its frame, initializes it
 * to 0, and points `exit_code` at it. This keeps `ctx` const-honest — the struct's
 * pointer field never mutates, only the pointee does, which was never const.
 * Native commands that never touch the pointer leave the runner at 0 and exit
 * cleanly.
 */
typedef struct dotta_ctx {
    dotta_run_t run;                    /* By value: opened and closed in place by run_spec */
    arena_t *arena;                     /* Command-scoped; created before the open, freed after the close */
    const config_t *config;             /* Process-scoped, borrowed */
    output_t *out;
    int argc;                           /* Original process argc */
    char **argv;                        /* Original process argv */
    int *exit_code;                     /* Non-NULL; the status the run exits with, where the dispatch sets one */
} dotta_ctx_t;

/**
 * Accessor for the root command registry.
 *
 * Returns the NULL-terminated `args_command_t *const []` defined as `static`
 * data in main.c. The pointer is borrowed; never freed by the caller. Only consumer
 * today is `cmds/completion.c`: it projects the registry into the fish-completion
 * script (`make completions`) and resolves the shell's command line against it
 * when asked for candidates.
 *
 * The accessor exists so the cmds/ layer can read the registry without
 * compile-depending on the registry symbol itself — the storage stays file-local
 * in main.c, and this function is its typed public face.
 */
const struct args_command *const *dotta_registry(void);

#endif /* DOTTA_RUNTIME_H */
