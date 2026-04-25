/**
 * runtime.h - Cross-layer contract between main.c and the cmds/ layer
 *
 * Declares the types every command handler reads, the payloads every
 * command spec declares, and the accessor through which the cmds/ layer
 * reaches the root registry without naming its storage symbol. The
 * dispatch *implementation* (registry array, run_spec, resource-acquisition
 * helpers) stays file-local in main.c; this header is the typed surface
 * it exposes.
 *
 * Contents:
 *   - `dotta_repo_mode_t`   — repo-open contract honored by the dispatcher;
 *   - `dotta_state_mode_t`  — state-open contract honored by the dispatcher;
 *   - `dotta_crypto_mode_t` — crypto-resources contract (keymgr +/- content_cache);
 *   - `dotta_spec_ext_t`    — payload referenced by `args_command_t::payload`,
 *                             letting each command declare its dispatch
 *                             preconditions in a typed way without the
 *                             base/args engine learning the enums;
 *   - `dotta_ctx_t`         — bundle handed to each command's dispatch
 *                             handler (repo, state, keymgr, cache, config, ...);
 *   - `dotta_ext_*`         — one per (repo_mode, state_mode, crypto_mode)
 *                             combination actually used; commands point
 *                             `payload` at the constant matching their need;
 *   - `dotta_registry()`    — typed accessor for the root registry,
 *                             consumed by `cmds/completion.c` when exporting
 *                             the fish completion script.
 */

#ifndef DOTTA_RUNTIME_H
#define DOTTA_RUNTIME_H

#include <types.h>          /* error_t, arena_t, config_t, output_t */

/* libgit2's opaque repo type. Consumers that touch the pointer must
 * `#include <git2.h>` for the API; this header stays free of the
 * libgit2 dependency so it can be included transitively without
 * forcing every TU through git2.h. */
struct git_repository;

/* Core state handle. The full API lives in `src/core/state.h`; consumers
 * that call state functions include that header. Redeclaring the typedef
 * here keeps the contract typed without pulling core/ into every TU that
 * reaches ctx. C11 §6.7p3 permits a typedef name to be redeclared to the
 * same type, so this coexists with core/state.h's identical typedef in
 * any TU that includes both. Mirrors the struct-tag forward decl above. */
typedef struct state state_t;

/* Crypto handles. Full APIs in `crypto/keymgr.h` and `infra/content.h`;
 * TUs that call their functions include those headers. */
typedef struct keymgr keymgr;
typedef struct content_cache content_cache_t;

/* Spec-engine command descriptor. Forward-declared (rather than pulling
 * `base/args.h`) so that every TU that transitively includes
 * `runtime.h` does not drag the full `args_command_t` definition
 * through its compile. Same rationale as the `struct git_repository`
 * forward decl above, and the pattern `include/types.h` uses for
 * `error_t` / `arena_t`. */
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
 * State-opening contract honored by the dispatcher.
 *
 * Each command declares its state needs alongside its repo needs on the
 * same `dotta_spec_ext_t` payload. Main.c reads the mode in `run_spec`
 * *after* opening the repo and acquires the handle accordingly. If
 * `repo_mode` produces no repo handle (NONE, or OPTIONAL_SILENT with a
 * missing repo), state_mode is silently skipped and `ctx->state` stays
 * NULL.
 *
 * Commands that declare READ may still take scoped write transactions
 * via `state_begin` / `state_commit` on the borrowed handle — mirroring
 * today's update.c / revert.c / remove.c pattern. Commands that declare
 * WRITE hold `BEGIN IMMEDIATE` for the lifetime of dispatch and call
 * `state_save` when their mutation is complete; `state_free` in the
 * dispatcher rolls back any uncommitted transaction.
 *
 * CREATE-style commands (init, clone) declare NONE and open state
 * themselves, because the database file does not exist before dispatch
 * runs — there is nothing for `run_spec` to acquire. This parallels
 * their `DOTTA_REPO_NONE` declaration: both resources are self-owned
 * during creation.
 */
typedef enum dotta_state_mode {
    DOTTA_STATE_NONE,   /* No state handle acquired */
    DOTTA_STATE_READ,   /* state_load; scoped writes via state_begin/state_commit */
    DOTTA_STATE_WRITE   /* state_open (BEGIN IMMEDIATE); command calls state_save */
} dotta_state_mode_t;

/**
 * Crypto-resources contract honored by the dispatcher.
 *
 * Each command declares its crypto needs on the same `dotta_spec_ext_t`
 * payload as repo/state modes. Main.c reads the mode in `run_spec`
 * *after* opening state and acquires the handles accordingly. Both
 * handles are borrowed by the handler; the dispatcher tears them down
 * LIFO (cache, then keymgr) before state teardown.
 *
 * Mode split rationale
 * --------------------
 *   - KEY is enough for commands that read or write a single blob via
 *     the non-caching content API (`add` writes; `show`, `revert` read
 *     single blobs). 4 of 9 crypto-aware commands want only this.
 *   - KEY_CACHE is required by commands that iterate workspace divergence
 *     or a historical manifest, where the same blob OID can be fetched
 *     multiple times (`apply`, `diff`, `status`, `sync`, `update`).
 *
 * Disabled-encryption semantics
 * -----------------------------
 * When `config->encryption_enabled == false`, `ctx->keymgr` stays NULL
 * regardless of mode. Under KEY_CACHE the cache is still created (with
 * NULL keymgr) so callers deal with one shape. Under KEY, both handles
 * stay NULL. Handlers forward `ctx->keymgr` to the content layer
 * unconditionally — it surfaces ERR_CRYPTO with a user-facing message
 * naming the file if a per-file operation asks to encrypt or decrypt
 * without a key, so commands never need to gate on "do I have a key?"
 * before calling through.
 */
typedef enum dotta_crypto_mode {
    DOTTA_CRYPTO_NONE,        /* Neither handle acquired */
    DOTTA_CRYPTO_KEY,         /* ctx->keymgr only (NULL if encryption disabled) */
    DOTTA_CRYPTO_KEY_CACHE    /* Both; cache always acquired, keymgr may be NULL */
} dotta_crypto_mode_t;

/**
 * Per-command extension payload referenced by `args_command_t::payload`.
 *
 * Carries the declarative dispatch preconditions each command has.
 * Additional fields (privilege escalation, verbosity override, etc.)
 * land here as new members without touching the engine — this is the
 * extension point `main.c::run_spec` reads.
 */
typedef struct dotta_spec_ext {
    dotta_repo_mode_t repo_mode;
    dotta_state_mode_t state_mode;
    dotta_crypto_mode_t crypto_mode;
} dotta_spec_ext_t;

/**
 * Dispatch context — populated by the dispatcher, read by each command.
 *
 * Bundling is deliberate: future additions (signal cancellation,
 * verbosity override, etc.) land as struct members, not dispatch-signature
 * churn across every command.
 *
 * Invariants
 * ----------
 *   - `repo != NULL`  iff  `repo_path != NULL`. `repo_open` already
 *     resolves the path to open the repo; threading it out costs
 *     nothing and gives commands that need both (e.g. bootstrap, which
 *     exports DOTTA_REPO_DIR to child scripts) a single source of truth
 *     instead of a second `resolve_repo_path` call.
 *   - `state != NULL`  iff  `state_mode != NONE AND repo != NULL`. A
 *     spec declaring STATE_READ or STATE_WRITE on a repo_mode that
 *     produced a handle receives a borrowed state; dispatch closes it
 *     on return. Commands never free `ctx->state`.
 *   - `content_cache != NULL`  iff  `crypto_mode == KEY_CACHE AND
 *     repo != NULL`. The cache carries a borrowed pointer to
 *     `ctx->keymgr` (which may be NULL if encryption is disabled) and
 *     is torn down before the keymgr.
 *   - `keymgr != NULL` implies `config->encryption_enabled`. A spec
 *     declaring KEY or KEY_CACHE on a disabled config receives NULL
 *     keymgr; handlers forward the NULL straight into the content
 *     layer, which returns ERR_CRYPTO with a user-facing message if
 *     any per-file operation actually asks to encrypt or decrypt. No
 *     caller-side gate is required.
 *
 * Members not welcome on this struct
 * ----------------------------------
 * The following patterns have been rejected by the design and must not
 * be added without first re-evaluating the whole ownership model:
 *
 *   1. No invalidation API on ctx for any field. Command-scoped
 *      resources do not need invalidation; a need to "clear" a
 *      resource mid-command is an API operation on the borrowed handle
 *      (e.g. `keymgr_clear(ctx->keymgr)` inside `dotta key clear`),
 *      not a ctx-layer concern.
 *   2. No lazy accessors (`dotta_ctx_get_X(ctx)` that construct on
 *      first call). Fields are populated eagerly by dispatch before
 *      the handler runs, so handlers see a fixed shape.
 *   3. No "reach inside workspace to borrow its resource" pattern.
 *      Resources that multiple dispatch steps share live on ctx; there
 *      is never a `workspace_get_X` / `state_get_X` accessor that
 *      exposes ctx-scope resources via a lower layer.
 *   4. No raw scratch arena on ctx. The parser's arena lives on
 *      `run_spec`'s frame and is not handed to handlers. A handler that
 *      needs an arena creates one with the lifetime of its operation
 *      (e.g. `arena_t *a = arena_create(0)` at function entry,
 *      `arena_destroy(a)` at exit). The parser's arena lifetime is
 *      "command dispatch"; handler scratch lifetime is "this operation,"
 *      which is *nested* inside dispatch but not the same. Bundling them
 *      would force a future invalidator (Rule 5).
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
    state_t *state;                     /* NULL unless state_mode acquires; borrowed */
    keymgr *keymgr;                     /* NULL unless crypto_mode acquires + encryption enabled */
    content_cache_t *content_cache;     /* NULL unless crypto_mode == KEY_CACHE */
    const config_t *config;
    output_t *out;
    int argc;                           /* Original process argc */
    char **argv;                        /* Original process argv */
    int *exit_code;                     /* Non-NULL; *exit_code overrides exit when err==NULL */
} dotta_ctx_t;

/* Per-combination payloads. Each command's spec sets `.payload =
 * &dotta_ext_X` for its needed (repo_mode, state_mode, crypto_mode) */
extern const dotta_spec_ext_t dotta_ext_none;          /* NONE,            NONE,  NONE      */
extern const dotta_spec_ext_t dotta_ext_path_only;     /* PATH_ONLY,       NONE,  NONE      */
extern const dotta_spec_ext_t dotta_ext_repo_only;     /* REQUIRED,        NONE,  NONE      */
extern const dotta_spec_ext_t dotta_ext_read;          /* REQUIRED,        READ,  NONE      */
extern const dotta_spec_ext_t dotta_ext_write;         /* REQUIRED,        WRITE, NONE      */
extern const dotta_spec_ext_t dotta_ext_read_silent;   /* OPTIONAL_SILENT, READ,  NONE      */
extern const dotta_spec_ext_t dotta_ext_read_key;      /* REQUIRED,        READ,  KEY       */
extern const dotta_spec_ext_t dotta_ext_write_key;     /* REQUIRED,        WRITE, KEY       */
extern const dotta_spec_ext_t dotta_ext_read_crypto;   /* REQUIRED,        READ,  KEY_CACHE */
extern const dotta_spec_ext_t dotta_ext_write_crypto;  /* REQUIRED,        WRITE, KEY_CACHE */

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
