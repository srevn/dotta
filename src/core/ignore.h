/**
 * ignore.h - Multi-layered ignore pattern system
 *
 * All user-authored rules (baseline, profile, config, CLI) compile into
 * a single gitignore ruleset at context creation. Rules are appended in
 * precedence order and evaluated with last-match-wins semantics, so
 * `!`-negation works across layers — a profile can un-ignore a baseline
 * pattern, config can un-ignore a profile pattern, and CLI (highest
 * precedence) can un-ignore anything below.
 *
 * Precedence (lowest to highest):
 *   1. Baseline .dottaignore on `dotta-worktree` (machine-local;
 *      seeded by `dotta init`/`clone`, editable via `dotta ignore`).
 *      If absent, compiled defaults are used instead (origin=BUILTIN).
 *   2. Profile .dottaignore on the profile branch.
 *   3. Config ignore patterns (user-level rules from config.toml).
 *   4. CLI --exclude flags (per-operation, highest priority).
 *
 * The source tree's own `.gitignore` (when the user is adding files
 * from inside another git repo) is a separate mechanism: see
 * `sys/source.h` for `source_filter_t`. Callers that want that
 * behaviour construct a `source_filter_t` alongside the ignore
 * context and consult both explicitly.
 *
 * Full .gitignore grammar is supported:
 *   - Glob patterns (*, ?, [abc]) and recursive globs (double-star)
 *   - Directory matching (trailing /)
 *   - Negation patterns (!) — now honored in CLI and config too
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

/**
 * Ignore context — a compiled `.dottaignore` ruleset.
 *
 * Create once per operation (or per profile, when iterating), reuse for
 * multiple path checks. The context does not mutate the dotta repository
 * handle, so multiple contexts against the same repo are safe and
 * independent.
 */
typedef struct ignore_context ignore_context_t;

/**
 * Ignore source layer (for diagnostic purposes)
 */
typedef enum {
    IGNORE_SOURCE_NONE = 0,              /* Not ignored */
    IGNORE_SOURCE_CLI,                   /* CLI --exclude patterns */
    IGNORE_SOURCE_PROFILE_DOTTAIGNORE,   /* Profile-specific .dottaignore */
    IGNORE_SOURCE_BASELINE_DOTTAIGNORE,  /* Baseline .dottaignore on dotta-worktree */
    IGNORE_SOURCE_BUILTIN,               /* Compiled defaults (baseline fallback) */
    IGNORE_SOURCE_CONFIG                 /* Config file patterns */
} ignore_source_t;

/**
 * Test result with diagnostic information
 */
typedef struct {
    bool ignored;               /* Whether path is ignored */
    ignore_source_t source;     /* Which layer caused the ignore */
} ignore_test_result_t;

/**
 * Create ignore context.
 *
 * Loads baseline and profile .dottaignore from the repository, then
 * appends config patterns and CLI excludes, compiling all layers into
 * a single ruleset. Returns an owned context the caller frees with
 * `ignore_context_free`.
 *
 * Lifetime:
 *   - `repo` is read only during construction (baseline/profile tree
 *     loads); it does not need to outlive the returned context.
 *   - `config`, `profile`, and `cli_excludes` are copied internally.
 *   - Multiple contexts against the same repo are safe and independent.
 *
 * Input validation:
 *   - Maximum CLI patterns: 10,000 (ERR_VALIDATION if exceeded).
 *   - Maximum config patterns: 10,000 (ERR_VALIDATION if exceeded).
 *   - Maximum pattern length: 4,096 chars (ERR_VALIDATION if exceeded).
 *   - Maximum .dottaignore blob size: 1 MB (ERR_VALIDATION if exceeded).
 *
 * @param repo Repository — borrowed only during this call, can be NULL
 * @param config Configuration — can be NULL
 * @param profile Profile name — can be NULL or empty
 * @param cli_excludes CLI --exclude patterns — can be NULL
 * @param cli_exclude_count Number of CLI patterns
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_context_create(
    git_repository *repo,
    const config_t *config,
    const char *profile,
    char **cli_excludes,
    size_t cli_exclude_count,
    ignore_context_t **out
);

/**
 * Free ignore context
 *
 * @param ctx Context to free (can be NULL)
 */
void ignore_context_free(ignore_context_t *ctx);

/**
 * Check if path should be ignored.
 *
 * Evaluates the compiled ruleset (baseline/builtin + profile + config
 * + CLI) with last-match-wins semantics. Callers that also want to
 * consult the source tree's own `.gitignore` pair this with
 * `source_filter_is_excluded` from `sys/source.h`.
 *
 * @param ctx Ignore context (must not be NULL)
 * @param path Path to check (relative or absolute)
 * @param is_directory Whether path is a directory
 * @param ignored Output boolean (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_should_ignore(
    ignore_context_t *ctx,
    const char *path,
    bool is_directory,
    bool *ignored
);

/**
 * Get default .dottaignore content
 *
 * Returns sensible default patterns for common unwanted files.
 * Used as the baseline seed on `dotta init` / `dotta clone`, as the
 * fallback source when baseline is absent, and for `dotta ignore
 * --list-defaults`.
 *
 * @return Default .dottaignore content (static string, do not free)
 */
const char *ignore_default_dottaignore_content(void);

/**
 * Seed baseline .dottaignore on dotta-worktree
 *
 * Commits the compiled default patterns to `.dottaignore` on the
 * `dotta-worktree` branch. Called by `dotta init` and `dotta clone` so
 * every repo has a visible, editable starting point for machine-local
 * ignore extensions.
 *
 * Idempotent: `gitops_update_file` detects a no-op when the blob
 * already matches HEAD, so repeated invocations don't create empty
 * commits. Because the target is the currently-checked-out branch,
 * the same call also brings INDEX and workdir into line with HEAD
 * for the seeded file — no follow-up sync needed.
 *
 * @param repo Repository (must not be NULL; must have dotta-worktree branch)
 * @return Error or NULL on success
 */
error_t *ignore_seed_baseline(git_repository *repo);

/**
 * Get profile .dottaignore template
 *
 * Returns a minimal template for new profile .dottaignore files.
 * Includes clear documentation about the layering system and baseline inheritance.
 * Used when creating new profiles to provide a clean starting point.
 *
 * @return Profile .dottaignore template (static string, do not free)
 */
const char *ignore_profile_dottaignore_template(void);

/**
 * Load raw .dottaignore blob from a branch into an owned buffer.
 *
 * Returns (*out_content=NULL, *out_size=0) when any of:
 *   - The branch does not exist
 *   - The branch exists but contains no .dottaignore at the tree root
 *   - The .dottaignore blob is empty (size == 0)
 *
 * None of these produce an error; they just mean "no content". Only I/O
 * failures, malformed trees, OOM, or size-cap violations (>1MB) return
 * an error.
 *
 * On success with non-NULL content, *out_content is a heap-allocated,
 * NUL-terminated buffer of *out_size bytes. The caller owns and frees it.
 *
 * @param repo Repository (must not be NULL)
 * @param branch_name Short branch name, e.g. "dotta-worktree" (must not be NULL or empty)
 * @param out_content Output content (must not be NULL); set to NULL if absent
 * @param out_size Output size in bytes (may be NULL if caller does not need it)
 * @return Error or NULL on success
 */
error_t *ignore_load_raw_content(
    git_repository *repo,
    const char *branch_name,
    char **out_content,
    size_t *out_size
);

/**
 * Test if path should be ignored (with diagnostic info)
 *
 * Like ignore_should_ignore(), but returns which layer caused the
 * ignore. Useful for debugging and the `dotta ignore --test` command.
 * Covers only the four `.dottaignore` layers; the source tree's own
 * `.gitignore` is reported separately by the caller via
 * `sys/source.h`.
 *
 * @param ctx Ignore context (must not be NULL)
 * @param path Path to check (relative or absolute)
 * @param is_directory Whether path is a directory
 * @param result Output result (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_test_path(
    ignore_context_t *ctx,
    const char *path,
    bool is_directory,
    ignore_test_result_t *result
);

/**
 * Convert ignore source to human-readable string
 *
 * @param source Ignore source
 * @return Human-readable string (static, do not free)
 */
const char *ignore_source_to_string(ignore_source_t source);

#endif /* DOTTA_IGNORE_H */
