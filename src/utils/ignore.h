/**
 * ignore.h - Multi-layered ignore pattern system
 *
 * Implements a comprehensive ignore system with four layers of precedence:
 *   1. CLI --exclude flags (highest priority - operation-specific)
 *   2. Combined .dottaignore (baseline + profile-specific)
 *      - Baseline .dottaignore from dotta-worktree (applies to all profiles)
 *      - Profile .dottaignore extends baseline (can use ! to override)
 *      - Profile starts empty and inherits all baseline patterns
 *   3. Config ignore patterns (machine-specific rules from config.toml)
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

#include "types.h"
#include "utils/config.h"

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
    IGNORE_SOURCE_BASELINE_DOTTAIGNORE,  /* Baseline .dottaignore */
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
 * @param repo Repository (for accessing .dottaignore files)
 * @param config Configuration (for config patterns and settings)
 * @param profile_name Profile name (for profile-specific .dottaignore, can be NULL)
 * @param cli_excludes CLI --exclude patterns (can be NULL)
 * @param cli_exclude_count Number of CLI patterns
 * @param out Ignore context (must not be NULL)
 * @return Error or NULL on success
 */
error_t *ignore_context_create(
    git_repository *repo,
    const dotta_config_t *config,
    const char *profile_name,
    const char **cli_excludes,
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
 *   2. Combined .dottaignore (baseline + profile with negation support)
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
 * Used by `dotta init` to create initial .dottaignore.
 *
 * @return Default .dottaignore content (static string, do not free)
 */
const char *ignore_default_dottaignore_content(void);

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
