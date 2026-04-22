/**
 * ignore.h - Layered `.dottaignore` ruleset builder and persistence.
 *
 * Dotta composes four user-authored layers into a single gitignore
 * ruleset per operation:
 *
 *   1. Baseline `.dottaignore` on `dotta-worktree` (machine-local;
 *      seeded by `dotta init` / `dotta clone`, editable via
 *      `dotta ignore`). Falls back to compiled defaults when absent.
 *   2. Profile `.dottaignore` on the profile branch.
 *   3. Config ignore patterns (user-level rules from config.toml).
 *   4. CLI `--exclude` flags (per-operation, highest priority).
 *
 * Rules from later layers override earlier ones via last-match-wins
 * semantics, so cross-layer negation works: a profile can un-ignore a
 * baseline pattern, CLI can un-ignore anything below, etc.
 *
 * The source tree's own `.gitignore` (when the user runs `dotta add`
 * against files that live inside a different git repository) is a
 * separate mechanism in `sys/source.h`. Callers that want that
 * behaviour build a `source_filter_t` alongside and consult it
 * explicitly.
 *
 * Runtime shape
 * -------------
 * A consumer builds one `ignore_rules_t` per command via
 * `ignore_rules_create`. Profile-specific rulesets are produced on
 * demand by `ignore_rules_for_profile`, which returns a borrowed
 * `const gitignore_ruleset_t *` the caller passes directly to
 * `gitignore_is_ignored()` or `gitignore_eval()`. Per-profile
 * rulesets are memoised for the builder's lifetime.
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

/* Forward declarations — the full headers pull in plenty of machinery
 * we do not want every consumer of core/ignore.h to transitively
 * include. Both types already typedef identically elsewhere */
typedef struct gitignore_ruleset gitignore_ruleset_t;
typedef struct worktree_handle worktree_handle_t;

/**
 * Layered-ruleset builder — command-scoped.
 *
 * Loads the common layers (baseline / builtin, config, CLI) once on
 * construction and builds per-profile rulesets lazily. Each ruleset
 * returned by `ignore_rules_for_profile` is a self-contained evaluator
 * usable with any `base/gitignore` primitive.
 *
 * Lifetime: command-scoped. Per-profile rulesets are memoised for the
 * life of the builder; pointers returned by `ignore_rules_for_profile`
 * stay valid until `ignore_rules_free`.
 *
 * Thread safety: not thread-safe.
 */
typedef struct ignore_rules ignore_rules_t;

/**
 * Origin of the rule that decided a match.
 *
 * Declared in ascending precedence so a larger numeric value means
 * "this layer overrides lower ones." Values round-trip through
 * `gitignore_origin_t` (8-bit) when the builder tags rules during
 * append; a `_Static_assert` in ignore.c guards against truncation if
 * this enum ever grows past UINT8_MAX.
 */
typedef enum {
    IGNORE_ORIGIN_NONE = 0,   /* No rule matched */
    IGNORE_ORIGIN_BUILTIN,    /* Compiled defaults (fallback when baseline absent) */
    IGNORE_ORIGIN_BASELINE,   /* Baseline .dottaignore on dotta-worktree */
    IGNORE_ORIGIN_PROFILE,    /* Profile .dottaignore on its branch */
    IGNORE_ORIGIN_CONFIG,     /* Config file patterns */
    IGNORE_ORIGIN_CLI,        /* --exclude flags (highest priority) */
    IGNORE_ORIGIN_COUNT_      /* Sentinel; not a value */
} ignore_origin_t;

/**
 * Create the layered-ruleset builder.
 *
 * Loads the baseline `.dottaignore` from `dotta-worktree` (falling
 * back to compiled defaults when absent) and captures the config and
 * CLI pattern arrays for per-profile composition. Does not touch the
 * profile branch until `ignore_rules_for_profile` is called.
 *
 * Lifetime / ownership:
 *   - `repo` is borrowed; the builder must not outlive the repo handle.
 *   - `config->ignore_patterns` and `cli_excludes` are borrowed; the
 *     backing arrays and their string entries must outlive the
 *     builder. In practice both are command-scoped.
 *
 * Input validation (enforced by the underlying gitignore engine):
 *   - Per-pattern length: 4096 bytes.
 *   - Per-ruleset rule count: 10,000.
 *   - `.dottaignore` blob size: 1 MB.
 *
 * @param repo         Repository (must not be NULL)
 * @param config       Configuration (may be NULL)
 * @param cli_excludes CLI --exclude patterns (may be NULL when count == 0)
 * @param cli_count    Number of CLI patterns
 * @param out          Output handle (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_rules_create(
    git_repository *repo,
    const config_t *config,
    char *const *cli_excludes,
    size_t cli_count,
    ignore_rules_t **out
);

/**
 * Free the builder and every memoised ruleset it holds.
 *
 * @param rules Builder (may be NULL)
 */
void ignore_rules_free(ignore_rules_t *rules);

/**
 * Resolve the ruleset to use for `profile`.
 *
 * The returned pointer is borrowed from the builder's arena and
 * stays valid until `ignore_rules_free`. Repeated calls with the
 * same profile name return the same pointer — the ruleset is built
 * on first use and cached.
 *
 * `profile` may be NULL or empty to request the baseline-only
 * ruleset (baseline/builtin + config + CLI, no per-profile layer).
 *
 * A non-existent profile branch is not an error: the profile layer
 * simply contributes no rules. Callers that need "profile exists"
 * semantics check with `profile_exists` first.
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
 * Accepts the origin returned by `gitignore_eval` (as stored in the
 * match result) after the caller's cast to `ignore_origin_t`.
 *
 * @param origin Origin tag
 * @return Human-readable static string (never NULL, never to be freed)
 */
const char *ignore_origin_describe(ignore_origin_t origin);

/**
 * Read a `.dottaignore` blob from a branch into a heap buffer.
 *
 * Returns (*out_content = NULL, *out_size = 0) without error when any
 * of the following hold:
 *   - The branch does not exist
 *   - The branch has no `.dottaignore` at its tree root
 *   - The blob is empty
 *
 * Only I/O failures, malformed trees, OOM, or the 1 MB size cap
 * produce an error.
 *
 * On success with non-NULL content, `*out_content` is a heap-allocated
 * NUL-terminated buffer of `*out_size` bytes. The caller owns it.
 *
 * @param repo        Repository (must not be NULL)
 * @param branch      Short branch name (must not be NULL or empty)
 * @param out_content Output content (must not be NULL); NULL when absent
 * @param out_size    Output size in bytes (may be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_blob_read(
    git_repository *repo,
    const char *branch,
    char **out_content,
    size_t *out_size
);

/**
 * Write `content` as the `.dottaignore` blob on `branch`, creating a
 * commit with `commit_msg`.
 *
 * Idempotent: no-ops (no commit) when the blob already matches HEAD.
 * Rejects writes above the 1 MB cap up front — symmetric with
 * `ignore_blob_read`, so an editor buffer that somehow grew past the
 * cap fails cleanly instead of committing a blob that later refuses
 * to load.
 *
 * When `branch` is the currently-checked-out branch,
 * `gitops_update_file` keeps the INDEX and workdir in sync — no
 * follow-up sync needed.
 *
 * @param repo       Repository (must not be NULL)
 * @param branch     Short branch name (must not be NULL or empty)
 * @param content    Blob content (must not be NULL; may be empty)
 * @param size       Size in bytes (must be <= 1 MB)
 * @param commit_msg Commit message (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_blob_write(
    git_repository *repo,
    const char *branch,
    const char *content,
    size_t size,
    const char *commit_msg
);

/**
 * Seed the baseline `.dottaignore` on `dotta-worktree`.
 *
 * Writes the compiled default patterns. Called by `dotta init` and
 * `dotta clone` so every repo has a visible, editable starting point
 * for machine-local ignore extensions. Idempotent via
 * `ignore_blob_write`'s no-op detection.
 *
 * @param repo Repository (must not be NULL; must have dotta-worktree)
 * @return Error or NULL on success
 */
error_t *ignore_seed_baseline(git_repository *repo);

/**
 * Seed a new profile's `.dottaignore` by writing the template into
 * the worktree and staging it for the next commit.
 *
 * Called by `dotta add` when creating a new profile branch. The
 * caller's normal commit flow picks up the staged file — this
 * primitive does not itself create a commit.
 *
 * @param wt Worktree handle (must not be NULL; must be checked out
 *           on the new profile's branch)
 * @return Error or NULL on success
 */
error_t *ignore_seed_profile(worktree_handle_t *wt);

/**
 * Default baseline `.dottaignore` content.
 *
 * Used as the init/clone seed and as the implicit fallback when the
 * baseline blob is missing or empty.
 *
 * @return Static NUL-terminated string (never to be freed)
 */
const char *ignore_baseline_defaults(void);

/**
 * Profile `.dottaignore` template.
 *
 * Minimal starter content documenting the layering model and
 * baseline inheritance. Used by `dotta add` when initialising a new
 * profile branch and by `dotta ignore` when seeding an editor
 * session for an empty profile.
 *
 * @return Static NUL-terminated string (never to be freed)
 */
const char *ignore_profile_template(void);

#endif /* DOTTA_IGNORE_H */
