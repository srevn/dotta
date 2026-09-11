/**
 * ignore.h - Layered `.dottaignore` ruleset builder and persistence.
 *
 * Dotta composes four user-authored layers into a single gitignore ruleset per
 * operation:
 *
 *   1. Baseline `.dottaignore` at `refs/dotta/baseline` (this machine's;
 *      seeded by `dotta init` / `dotta clone`, editable via `dotta ignore`).
 *      Falls back to compiled defaults when absent.
 *   2. Profile `.dottaignore` on the profile branch.
 *   3. Config ignore patterns (user-level rules from config.toml).
 *   4. CLI `--exclude` flags (per-operation, highest priority).
 *
 * Rules from later layers override earlier ones via last-match-wins semantics,
 * so cross-layer negation works: a profile can un-ignore a baseline pattern,
 * CLI can un-ignore anything below, etc. What a later layer can un-ignore is a
 * *pattern*, not a directory an earlier layer excluded: the layers compile into
 * one ruleset and the ruleset is read as git reads one — the ancestors first,
 * and an excluded directory final (base/gitignore.h). A baseline `.cache/` is
 * not re-opened by a profile's `!.cache/keep`; `!.cache/` re-opens it, and then
 * the rules beneath have their say.
 *
 * The source tree's own `.gitignore` (when the user runs `dotta add` against
 * files that live inside a different git repository) is a separate mechanism in
 * `sys/source.h`. Callers that want that behaviour build a `source_filter_t`
 * alongside and consult it explicitly — where no layer above decided, so it is
 * the lowest layer and a `!` rule in any of the four overrides it.
 *
 * Runtime shape
 * -------------
 * A consumer builds one `ignore_rules_t` per command via `ignore_rules_create`.
 * Profile-specific rulesets are produced on demand by `ignore_rules_for_profile`,
 * which returns a borrowed `const gitignore_ruleset_t *` the caller passes directly
 * to `gitignore_is_ignored()` or `gitignore_eval()`. Per-profile rulesets are
 * memoised for the builder's lifetime.
 *
 * The subject
 * -----------
 * A ruleset is evaluated against the mount-relative path — `mount_strip_label`
 * of the storage path, what a `.gitignore` at `~`, at `/` or at the deployment
 * target would see. Every consumer classifies what it found before it asks, and
 * asks with the tail: `.cache/` means `~/.cache` for a `home/` path and `/.cache`
 * for a `root/` one, and nothing above the mount root takes part.
 *
 * Full .gitignore grammar is supported:
 *   - Glob patterns (*, ?, [abc]) and `**` recursive globs
 *   - Directory matching (trailing /)
 *   - Negation patterns (!)
 *   - Comment lines (#)
 *   - Anchored patterns (leading /)
 *
 * Example cross-layer negation:
 *   Baseline .dottaignore:  *.log       (ignore all log files)
 *   Profile .dottaignore:   !debug.log  (un-ignore debug.log)
 *   Result: debug.log is NOT ignored in this profile
 */

#ifndef DOTTA_IGNORE_H
#define DOTTA_IGNORE_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

/* Forward declaration — the full header pulls in plenty of machinery we do not
 * want every consumer of core/ignore.h to transitively include. The type already
 * typedefs identically there */
typedef struct gitignore_ruleset gitignore_ruleset_t;

/**
 * The baseline's home: a ref of this machine's own.
 *
 * It stands beside the epoch in refs/dotta and differs from it in one way — the
 * epoch syncs, the baseline never does. Sync's unit is a branch and the clone
 * fetches branches and the epoch, so the ref is made by `dotta init` and `dotta
 * clone` (once, with the defaults) and moved only by `dotta ignore`; no remote
 * holds it, and the epoch's restore refspec names the epoch alone (infra/epoch.h)
 * so a hand fetch cannot replace it with a remote's. Local by decision, not by
 * accident: the profile's `.dottaignore` travels with the profile, the config's
 * patterns stay with the machine, and the baseline sits between — the repository's
 * layer by intent, this machine's for as long as sync's unit is a branch. The
 * day that unit is a ref, this is the first to travel.
 */
#define BASELINE_REF "refs/dotta/baseline"

/**
 * Layered-ruleset builder — command-scoped.
 *
 * Compiles the baseline once on construction, borrows the config's layer and
 * the CLI's, and builds per-profile rulesets lazily. Each ruleset returned by
 * `ignore_rules_for_profile` is a self-contained evaluator usable with any
 * `base/gitignore` primitive.
 *
 * Lifetime: the arena's. The builder, its profile cache and every ruleset
 * `ignore_rules_for_profile` returns are allocated in the arena
 * `ignore_rules_create` borrows, and live until that arena is destroyed — nothing
 * frees them one by one. Per-profile rulesets are memoised for the life of the
 * builder.
 *
 * Thread safety: not thread-safe.
 */
typedef struct ignore_rules ignore_rules_t;

/**
 * Origin of the rule that decided a match.
 *
 * Declared in ascending precedence so a larger numeric value means "this layer
 * overrides lower ones." Values round-trip through gitignore_origin_t (8-bit):
 * a layer's rules are tagged at its compile, and again where the builder composes
 * it.
 */
typedef enum {
    IGNORE_ORIGIN_NONE = 0,   /* No rule matched */
    IGNORE_ORIGIN_BUILTIN,    /* Compiled defaults (fallback when baseline absent) */
    IGNORE_ORIGIN_BASELINE,   /* Baseline .dottaignore at BASELINE_REF */
    IGNORE_ORIGIN_PROFILE,    /* Profile .dottaignore on its branch */
    IGNORE_ORIGIN_CONFIG,     /* Config file patterns */
    IGNORE_ORIGIN_CLI         /* --exclude flags (highest priority) */
} ignore_origin_t;

/**
 * Compile the `--exclude` patterns into the CLI layer: once per command, so every
 * question asked of them is one walk over compiled rules.
 *
 * Each pattern is one rule (gitignore_ruleset_append_pattern), tagged
 * IGNORE_ORIGIN_CLI. One the grammar refuses is refused under "Invalid --exclude
 * pattern", in the grammar's words, before the command acts — so a bad -e reads
 * the same on add, apply and update. Its readers: scope_build, whose filter apply
 * and update ask alone (scope_is_excluded says how), and add, which hands the
 * layer to ignore_rules_create as the builder's top layer.
 *
 * @param patterns The -e arguments (may be NULL when count is 0)
 * @param count    Number of patterns
 * @param arena    Arena the rules are compiled into (must not be NULL); it must
 *                 outlive every ruleset composed from the layer
 * @param out      The layer; NULL when count is 0 (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_excludes_compile(
    char *const *patterns,
    size_t count,
    arena_t *arena,
    const gitignore_ruleset_t **out
);

/**
 * Create the layered-ruleset builder.
 *
 * Reads and compiles the baseline `.dottaignore` at BASELINE_REF — the compiled
 * defaults when it is absent — once, for every profile the builder composes,
 * and borrows the config's layer and the CLI's. Does not touch the profile branch
 * until `ignore_rules_for_profile` is called.
 *
 * Lifetime / ownership:
 *   - `repo` is borrowed; the builder must not outlive the repo handle.
 *   - `arena` is borrowed; the builder allocates itself, the baseline's rules,
 *     the profile cache and per-profile rulesets into it, and every one of them
 *     lives until the arena is destroyed. In practice the arena is command-scoped
 *     (`ctx->arena`).
 *   - `config->ignore_ruleset` is borrowed, and so are the strings its rules
 *     hold: config_load compiled the layer into the config's arena, which lives
 *     for the process and so outlives every ruleset the builder returns.
 *   - `cli_rules` is borrowed, and so are the strings its rules hold: every
 *     per-profile ruleset copies those rules, so the arena they were compiled
 *     into must outlive every ruleset the builder returns. In practice both are
 *     command-scoped.
 *
 * Refused here: a baseline Git cannot read or that is not text ("Failed to load
 * baseline .dottaignore") and one that does not compile ("Failed to parse baseline
 * .dottaignore"). Refused at the first profile query: a profile's .dottaignore
 * that does not load, is not text or does not compile, and a composed ruleset
 * past the cap. The config's layer was refused, if at all, where the file was
 * loaded.
 *
 * Input validation:
 *   - Per-pattern length: 4096 bytes (the gitignore engine).
 *   - Per-ruleset rule count: 10,000 (the gitignore engine).
 *   - A `.dottaignore` blob: at most 1 MB, and text (ignore_blob_text).
 *
 * @param repo      Repository (must not be NULL)
 * @param config    Configuration (may be NULL)
 * @param cli_rules The CLI layer (ignore_excludes_compile); NULL when no -e
 * @param arena     Borrowed allocator for builder-owned data (must not be NULL)
 * @param out       Output handle (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_rules_create(
    git_repository *repo,
    const config_t *config,
    const gitignore_ruleset_t *cli_rules,
    arena_t *arena,
    ignore_rules_t **out
);

/**
 * Resolve the ruleset to use for `profile`.
 *
 * The returned pointer is borrowed from the builder's arena and stays valid for
 * the arena's life. Repeated calls with the same profile name return the same
 * pointer — the ruleset is built on first use and cached.
 *
 * `profile` may be NULL or empty to request the baseline-only ruleset
 * (baseline/builtin + config + CLI, no per-profile layer).
 *
 * A non-existent profile branch is not an error: the profile layer simply
 * contributes no rules. Callers that need "profile exists" semantics ask
 * `profile_require` first.
 *
 * @param rules   Builder (must not be NULL)
 * @param profile Profile name (may be NULL or "")
 * @param out     Output ruleset pointer (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_rules_for_profile(
    ignore_rules_t *rules,
    const char *profile,
    const gitignore_ruleset_t **out
);

/**
 * Describe an origin tag for diagnostic display.
 *
 * Accepts the origin returned by `gitignore_eval` (as stored in the match result)
 * after the caller's cast to `ignore_origin_t`.
 *
 * @param origin Origin tag
 * @return Human-readable static string (never NULL, never to be freed)
 */
const char *ignore_origin_describe(ignore_origin_t origin);

/**
 * Read a `.dottaignore` blob from a ref into a heap buffer: its bytes, as Git
 * holds them.
 *
 * The editor's read (cmds/ignore's edit mode), which hands the bytes to a human
 * and reads them back — the one reader that interprets nothing, and so the one
 * that can mend a file the others refuse. Every reader that interprets the file,
 * its rules or its lines, reads ignore_blob_text.
 *
 * Returns (*out_content = NULL, *out_size = 0) without error when any of the
 * following hold:
 *   - The ref does not exist
 *   - Its tree has no `.dottaignore` at the root
 *   - The blob is empty
 *
 * Only I/O failures, malformed trees, OOM, or the 1 MB size cap produce an error.
 *
 * On success with non-NULL content, `*out_content` is a heap-allocated
 * NUL-terminated buffer of `*out_size` bytes, which may hold a NUL of its own —
 * the size is its length, never strlen. The caller owns it.
 *
 * @param repo        Repository (must not be NULL)
 * @param refname     Full reference name — BASELINE_REF, or a profile's through
 *                    gitops_branch_refname (must not be NULL or empty)
 * @param out_content Output content (must not be NULL); NULL when absent
 * @param out_size    Output size in bytes (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_blob_read(
    git_repository *repo,
    const char *refname,
    char **out_content,
    size_t *out_size
);

/**
 * Read a `.dottaignore` blob as text: ignore_blob_read's bytes, refused when a
 * NUL stands among them (ERR_VALIDATION, naming the ref).
 *
 * A NUL would end every string reading of the file — the rules the builder
 * compiles, the lines `dotta ignore --add` and `--remove` rewrite — and whatever
 * stood behind it would be lost without a word. Its readers: ignore_rules_create
 * (the baseline), the per-profile build behind ignore_rules_for_profile, and
 * cmds/ignore's --add / --remove. The editor reads the bytes, so a file refused
 * here is mended by `dotta ignore`.
 *
 * Absent — no ref, no entry, an empty blob — as ignore_blob_read answers it.
 *
 * @param repo     Repository (must not be NULL)
 * @param refname  Full reference name — BASELINE_REF, or a profile's through
 *                 gitops_branch_refname (must not be NULL or empty)
 * @param out_text Output text, heap-allocated and owned by the caller (must not
 *                 be NULL); NULL when absent
 * @return Error or NULL on success
 */
error_t *ignore_blob_text(
    git_repository *repo,
    const char *refname,
    char **out_text
);

/**
 * Write `content` as the `.dottaignore` blob on `refname`, creating a commit
 * with `commit_msg`.
 *
 * One stage: open the ref, put the blob, commit — so a blob identical to the
 * ref's commits nothing (the stage's own rule), and the ref must exist
 * (ERR_NOT_FOUND otherwise; the callers verify it up front — the profile named,
 * or the baseline `dotta init` seeded). Refuses up front what ignore_blob_text
 * refuses — content past the 1 MB cap, or holding a NUL (ERR_VALIDATION) — so
 * an editor buffer that grew past the cap or took a NUL fails cleanly, instead
 * of committing a blob its readers would refuse.
 *
 * @param repo       Repository (must not be NULL)
 * @param refname    Full reference name — BASELINE_REF, or a profile's through
 *                   gitops_branch_refname (must not be NULL or empty)
 * @param content    Blob content (must not be NULL; may be empty)
 * @param size       Size in bytes (at most 1 MB, and no NUL among them)
 * @param commit_msg Commit message (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_blob_write(
    git_repository *repo,
    const char *refname,
    const char *content,
    size_t size,
    const char *commit_msg
);

/**
 * Seed the baseline `.dottaignore` at BASELINE_REF.
 *
 * Called by `dotta init` and `dotta clone` so every store has a visible, editable
 * starting point for this machine's ignore extensions: the defaults, as a root
 * commit on a ref that did not exist.
 *
 * Seed, not set: the ref's presence is the seed. It is made here and nowhere
 * else, and once it stands its tree is the user's — a pattern removed, the file
 * emptied, even the entry taken away by hand — and `dotta ignore` is how it
 * changes. `dotta init` is idempotent by re-running its steps, and this step's
 * idempotence is "the ref stands → nothing to do", never "rewrite with the
 * defaults", which is what `ignore_blob_write` does (it no-ops only on *identical*
 * content) and which once silently discarded a customised baseline on every
 * re-init. A ref that appears between the look and the seed's commit — two inits
 * racing — is refused by the stage, not seeded over.
 *
 * @param repo Repository (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_seed_baseline(git_repository *repo);

/**
 * Default baseline `.dottaignore` content.
 *
 * Used as the init/clone seed and as the implicit fallback when the baseline
 * blob is missing or empty.
 *
 * @return Static NUL-terminated string (never to be freed)
 */
const char *ignore_baseline_defaults(void);

/**
 * Profile `.dottaignore` template.
 *
 * Minimal starter content documenting the layering model and baseline inheritance.
 * Put on the stage by `dotta add` when it creates a profile branch, and used by
 * `dotta ignore` when seeding an editor session for an empty profile.
 *
 * @return Static NUL-terminated string (never to be freed)
 */
const char *ignore_profile_template(void);

#endif /* DOTTA_IGNORE_H */
