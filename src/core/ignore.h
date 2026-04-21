/**
 * ignore.h - Multi-layered ignore pattern system
 *
 * Implements a comprehensive ignore system with four tiers of precedence:
 *   1. CLI --exclude flags (highest priority - per-operation)
 *   2. Combined .dottaignore ruleset, evaluated as one libgit2 ruleset:
 *      - Baseline .dottaignore on dotta-worktree (machine-local, seeded
 *        with compiled defaults by `dotta init` and `dotta clone`, then
 *        editable via `dotta ignore`). If absent, compiled defaults are
 *        applied as a fallback so safety patterns stay active.
 *      - Profile .dottaignore on the profile branch (synced with the
 *        profile, editable via `dotta ignore <profile>`).
 *      Within the combined ruleset, later rules can negate earlier ones
 *      via `!` — so profile patterns may override baseline patterns,
 *      and baseline patterns may override the defaults fallback.
 *   3. Config ignore patterns (user-level rules from config.toml)
 *   4. Source .gitignore (lowest priority - when adding from git repos)
 *
 * Uses libgit2's gitignore parser for full .gitignore spec support:
 *   - Glob patterns (*, ?, [abc])
 *   - Directory matching (trailing /)
 *   - Negation patterns (!) - profile can negate baseline patterns
 *   - Comment lines (#)
 *   - Anchored patterns (leading /)
 *
 * Example negation workflow:
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
 * Ignore context - manages all ignore rules and precedence
 *
 * Holds state for all layers of ignore patterns.
 * Baseline and profile .dottaignore are combined to allow negation.
 * Create once per operation, reuse for multiple path checks.
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
    IGNORE_SOURCE_CONFIG,                /* Config file patterns */
    IGNORE_SOURCE_SOURCE_GITIGNORE       /* Source .gitignore */
} ignore_source_t;

/**
 * Test result with diagnostic information
 */
typedef struct {
    bool ignored;               /* Whether path is ignored */
    ignore_source_t source;     /* Which layer caused the ignore */
} ignore_test_result_t;

/**
 * Create ignore context
 *
 * Initializes the ignore system with all configured rules.
 *
 * Lifetime Requirements:
 *   - The repository pointer is borrowed (not owned). The caller MUST ensure
 *     the repository remains valid for the entire lifetime of the ignore context.
 *   - Freeing the repository before freeing the ignore context will result in
 *     use-after-free errors.
 *   - Only ONE ignore_context_t may be active per git_repository* at a time.
 *     The context mutates the repository's internal ignore rules (via libgit2).
 *     Creating a second context before freeing the first produces incorrect results.
 *   - The config and profile are copied internally and can be freed after
 *     this function returns.
 *   - CLI exclude patterns are copied internally and can be freed after this
 *     function returns.
 *
 * Input Validation:
 *   - Maximum CLI patterns: 10,000 (returns ERR_VALIDATION if exceeded)
 *   - Maximum config patterns: 10,000 (returns ERR_VALIDATION if exceeded)
 *   - Maximum pattern length: 4,096 characters (returns ERR_VALIDATION if exceeded)
 *   - Maximum .dottaignore file size: 1MB (returns ERR_VALIDATION if exceeded)
 *
 * @param repo Repository (for accessing .dottaignore files) - BORROWED, must outlive context
 * @param config Configuration (for config patterns and settings, can be NULL)
 * @param profile Profile name (for profile-specific .dottaignore, can be NULL)
 * @param cli_excludes CLI --exclude patterns (can be NULL)
 * @param cli_exclude_count Number of CLI patterns
 * @param out Ignore context (must not be NULL)
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
 * Check if path should be ignored
 *
 * Applies all ignore rules in precedence order:
 *   1. CLI excludes
 *   2. Combined .dottaignore ruleset (baseline-or-builtin + profile,
 *      evaluated as a single libgit2 ruleset with `!` negation)
 *   3. Config patterns
 *   4. Source .gitignore (if applicable and enabled)
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
 * Test if path should be ignored (with diagnostic info)
 *
 * Like ignore_should_ignore(), but returns which layer caused the ignore.
 * Useful for debugging and the 'dotta ignore --test' command.
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
