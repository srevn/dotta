/**
 * ignore.c - Multi-layered ignore pattern system implementation
 */

#include "ignore.h"

#include <fnmatch.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "base/error.h"
#include "base/gitops.h"
#include "utils/string.h"

/* Maximum path length for git repository discovery */
#ifndef GIT_PATH_MAX
#define GIT_PATH_MAX 4096
#endif

/* Input validation limits */
#define MAX_DOTTAIGNORE_SIZE (1024 * 1024)   /* 1MB - reasonable limit for ignore files */
#define MAX_PATTERN_LENGTH 4096              /* Maximum length for a single pattern */
#define MAX_PATTERN_COUNT 10000              /* Maximum number of patterns */

/**
 * Ignore context structure
 *
 * Layered ignore system:
 *   1. CLI patterns (highest priority)
 *   2. Combined .dottaignore (baseline from dotta-worktree + profile-specific)
 *      - Profile .dottaignore extends baseline, allowing negation to override
 *      - Example: baseline has "*.log", profile has "!important.log"
 *   3. Config patterns (machine-specific rules)
 *   4. Source .gitignore (lowest priority, when adding from git repos)
 */
struct ignore_context {
    /* CLI patterns (highest priority) */
    char **cli_patterns;
    size_t cli_pattern_count;

    /* Loaded ignore rules (libgit2) */
    git_repository *repo;                  /* Borrowed reference */
    char *baseline_dottaignore_content;    /* Baseline .dottaignore from dotta-worktree */
    char *profile_dottaignore_content;     /* Profile .dottaignore from profile branch */

    /* Config patterns (user-level) */
    char **config_patterns;
    size_t config_pattern_count;

    /* Settings */
    bool respect_gitignore;
};

/**
 * Baseline .dottaignore content with sensible defaults
 */
static const char *DEFAULT_DOTTAIGNORE =
    "# Dotta Ignore Patterns\n"
    "#\n"
    "# This file uses .gitignore syntax:\n"
    "#   - Use # for comments\n"
    "#   - Use * ? [abc] for glob patterns\n"
    "#   - Use / at end to match only directories\n"
    "#   - Use ! to negate a pattern\n"
    "#   - Use / at start to anchor to repo root\n"
    "\n"
    "# Temporary files\n"
    "*.tmp\n"
    "*.temp\n"
    "*.log\n"
    "*.bak\n"
    "*~\n"
    "*.swp\n"
    "*.swo\n"
    ".*.swp\n"
    ".*.swo\n"
    "\n"
    "# OS-specific\n"
    ".DS_Store\n"
    ".DS_Store?\n"
    ".localized\n"
    "._*\n"
    ".Spotlight-V100\n"
    ".Trashes\n"
    "Thumbs.db\n"
    "desktop.ini\n"
    "ehthumbs.db\n"
    "\n"
    "# Build artifacts and dependencies\n"
    "node_modules/\n"
    "__pycache__/\n"
    "*.pyc\n"
    "*.pyo\n"
    "*.o\n"
    "*.so\n"
    "*.dylib\n"
    "*.dll\n"
    "*.class\n"
    "*.jar\n"
    "target/\n"
    "build/\n"
    "dist/\n"
    "\n"
    "# Version control\n"
    ".git/\n"
    ".svn/\n"
    ".hg/\n"
    "\n"
    "# IDE and editor files\n"
    ".vscode/\n"
    ".idea/\n"
    ".nova/\n"
    "*.iml\n"
    ".project\n"
    ".classpath\n"
    ".settings/\n"
    "\n"
    "# Cache and temp directories\n"
    ".cache/\n"
    ".tmp/\n"
    ".temp/\n";

/**
 * Minimal .dottaignore template for new profiles
 *
 * Provides a clean starting point with clear documentation about the layering system.
 * Users can add profile-specific patterns or use negation (!) to override baseline.
 */
static const char *PROFILE_DOTTAIGNORE =
    "# Dotta Ignore Patterns\n"
    "#\n"
    "# This profile's ignore patterns work in layers (in precedence order):\n"
    "#   1. CLI --exclude flags (highest priority - per-operation)\n"
    "#   2. Baseline .dottaignore (from dotta-worktree branch, applies to ALL profiles)\n"
    "#   3. Profile .dottaignore (this file - extends baseline, can use ! to override)\n"
    "#   4. Config file patterns (from ~/.config/dotta/config.toml)\n"
    "#   5. Source .gitignore (lowest priority - when adding from git repos)\n"
    "#\n"
    "# IMPORTANT: This profile automatically inherits ALL baseline patterns.\n"
    "# Use negation patterns (!) to override baseline. Example:\n"
    "#   Baseline has: *.log\n"
    "#   Profile adds: !important.log\n"
    "#   Result: important.log is NOT ignored in this profile\n"
    "#\n"
    "# This file uses standard .gitignore syntax:\n"
    "#   - Use # for comments\n"
    "#   - Use * ? [abc] for glob patterns\n"
    "#   - Use / at end to match only directories\n"
    "#   - Use ! to negate a pattern (override baseline)\n"
    "#   - Use / at start to anchor to repo root\n"
    "\n"
    "# Add your profile-specific patterns below:\n";

/**
 * Load baseline .dottaignore from dotta-worktree branch
 *
 * This provides baseline ignore rules that apply to all profiles.
 * Profile-specific .dottaignore files extend this baseline and can use
 * negation patterns (!) to override baseline rules.
 */
static error_t *load_baseline_dottaignore(
    git_repository *repo,
    char **out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_content);

    *out_content = NULL;

    /* Check if dotta-worktree branch exists */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, "dotta-worktree", &branch_exists);
    if (err) {
        return err;
    }

    if (!branch_exists) {
        /* No dotta-worktree branch yet - not an error, just no .dottaignore */
        return NULL;
    }

    /* Load tree from dotta-worktree */
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, "refs/heads/dotta-worktree", &tree);
    if (err) {
        return error_wrap(err, "Failed to load dotta-worktree tree");
    }

    /* Look for .dottaignore entry */
    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (!entry) {
        /* No .dottaignore file - not an error */
        git_tree_free(tree);
        return NULL;
    }

    /* Get blob OID */
    const git_oid *oid = git_tree_entry_id(entry);
    if (!oid) {
        git_tree_free(tree);
        return ERROR(ERR_INTERNAL, "Failed to get .dottaignore OID");
    }

    /* Load blob */
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        git_tree_free(tree);
        return error_from_git(git_err);
    }

    /* Extract content */
    const void *raw_content = git_blob_rawcontent(blob);
    size_t size = git_blob_rawsize(blob);

    /* Validate size to prevent excessive memory allocation */
    if (size > MAX_DOTTAIGNORE_SIZE) {
        git_blob_free(blob);
        git_tree_free(tree);
        return ERROR(ERR_VALIDATION, "Baseline .dottaignore file too large (max 1MB)");
    }

    if (size > 0) {
        *out_content = malloc(size + 1);
        if (!*out_content) {
            git_blob_free(blob);
            git_tree_free(tree);
            return ERROR(ERR_MEMORY, "Failed to allocate .dottaignore content");
        }
        memcpy(*out_content, raw_content, size);
        (*out_content)[size] = '\0';
    }

    git_blob_free(blob);
    git_tree_free(tree);
    return NULL;
}

/**
 * Load profile-specific .dottaignore from a profile branch
 *
 * Profile .dottaignore extends the baseline .dottaignore.
 * Profiles start with an empty state and inherit all baseline patterns.
 * Use negation patterns (!) to un-ignore files matched by baseline patterns.
 *
 * Example:
 *   Baseline .dottaignore: *.log
 *   Profile .dottaignore:  !important.log
 *   Result: important.log is NOT ignored (negation overrides baseline)
 */
static error_t *load_profile_dottaignore(
    git_repository *repo,
    const char *profile_name,
    char **out_content
) {
    CHECK_NULL(repo);
    CHECK_NULL(out_content);

    *out_content = NULL;

    /* If no profile specified, return without error */
    if (!profile_name || profile_name[0] == '\0') {
        return NULL;
    }

    /* Check if profile branch exists */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, profile_name, &branch_exists);
    if (err) {
        return err;
    }

    if (!branch_exists) {
        /* Profile doesn't exist yet - not an error */
        return NULL;
    }

    /* Build ref name */
    char *ref_name = str_format("refs/heads/%s", profile_name);
    if (!ref_name) {
        return ERROR(ERR_MEMORY, "Failed to allocate ref name");
    }

    /* Load tree from profile branch */
    git_tree *tree = NULL;
    err = gitops_load_tree(repo, ref_name, &tree);
    free(ref_name);

    if (err) {
        /* Non-fatal: profile might not have .dottaignore */
        error_free(err);
        return NULL;
    }

    /* Look for .dottaignore entry */
    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (!entry) {
        /* No .dottaignore in this profile - not an error */
        git_tree_free(tree);
        return NULL;
    }

    /* Get blob OID */
    const git_oid *oid = git_tree_entry_id(entry);
    if (!oid) {
        git_tree_free(tree);
        return ERROR(ERR_INTERNAL, "Failed to get .dottaignore OID");
    }

    /* Load blob */
    git_blob *blob = NULL;
    int git_err = git_blob_lookup(&blob, repo, oid);
    if (git_err < 0) {
        git_tree_free(tree);
        return error_from_git(git_err);
    }

    /* Extract content */
    const void *raw_content = git_blob_rawcontent(blob);
    size_t size = git_blob_rawsize(blob);

    /* Validate size to prevent excessive memory allocation */
    if (size > MAX_DOTTAIGNORE_SIZE) {
        git_blob_free(blob);
        git_tree_free(tree);
        return ERROR(ERR_VALIDATION, "Profile .dottaignore file too large (max 1MB)");
    }

    if (size > 0) {
        *out_content = malloc(size + 1);
        if (!*out_content) {
            git_blob_free(blob);
            git_tree_free(tree);
            return ERROR(ERR_MEMORY, "Failed to allocate .dottaignore content");
        }
        memcpy(*out_content, raw_content, size);
        (*out_content)[size] = '\0';
    }

    git_blob_free(blob);
    git_tree_free(tree);
    return NULL;
}

/**
 * Check if path matches any CLI patterns using fnmatch
 */
static bool matches_cli_patterns(
    const char *path,
    char **patterns,
    size_t pattern_count
) {
    if (!path || !patterns || pattern_count == 0) {
        return false;
    }

    /* Extract basename for matching */
    const char *basename = strrchr(path, '/');
    if (basename) {
        basename++; /* Skip the '/' */
    } else {
        basename = path;
    }

    for (size_t i = 0; i < pattern_count; i++) {
        const char *pattern = patterns[i];

        /* Try matching full path */
        if (fnmatch(pattern, path, FNM_PATHNAME) == 0) {
            return true;
        }

        /* Try matching basename */
        if (fnmatch(pattern, basename, 0) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * Check if path matches .dottaignore patterns using libgit2
 */
static error_t *matches_dottaignore(
    git_repository *repo,
    const char *dottaignore_content,
    const char *path,
    bool is_directory,
    bool *matched
) {
    CHECK_NULL(matched);
    *matched = false;

    if (!repo || !dottaignore_content || !path) {
        return NULL;
    }

    /* Use libgit2's ignore API */
    int ignored = 0;

    /* Build path for checking - append / for directories */
    char *check_path = NULL;
    if (is_directory) {
        size_t len = strlen(path);
        if (len > 0 && path[len - 1] != '/') {
            check_path = str_format("%s/", path);
            if (!check_path) {
                return ERROR(ERR_MEMORY, "Failed to allocate path");
            }
        } else {
            check_path = strdup(path);
            if (!check_path) {
                return ERROR(ERR_MEMORY, "Failed to allocate path");
            }
        }
    } else {
        check_path = strdup(path);
        if (!check_path) {
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }
    }

    /* Add rules to libgit2 ignore system */
    int git_err = git_ignore_add_rule(repo, dottaignore_content);
    if (git_err < 0) {
        free(check_path);
        return error_from_git(git_err);
    }

    /* Check if path is ignored */
    git_err = git_ignore_path_is_ignored(&ignored, repo, check_path);

    /* Clean up the rule we just added */
    git_ignore_clear_internal_rules(repo);

    free(check_path);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    *matched = (ignored == 1);
    return NULL;
}

/**
 * Check if path matches config patterns
 */
static bool matches_config_patterns(
    const char *path,
    char **patterns,
    size_t pattern_count
) {
    /* Same logic as CLI patterns - uses fnmatch */
    return matches_cli_patterns(path, patterns, pattern_count);
}

/**
 * Check if path is ignored by source .gitignore
 *
 * Discovers if the path is within a git repository, and if so,
 * checks whether it's ignored by that repository's .gitignore.
 *
 * This prevents accidentally adding files that are already ignored
 * at the source location.
 */
static error_t *matches_source_gitignore(
    const char *abs_path,
    bool *matched
) {
    CHECK_NULL(abs_path);
    CHECK_NULL(matched);

    *matched = false;

    /* Discover git repository containing this path */
    git_buf discovered_path = GIT_BUF_INIT;
    int git_err = git_repository_discover(
        &discovered_path,
        abs_path,
        0,  /* Don't cross filesystem boundaries */
        NULL  /* No ceiling directories */
    );

    if (git_err < 0) {
        /* Not in a git repository - that's fine, not an error */
        if (git_err == GIT_ENOTFOUND) {
            return NULL;
        }
        /* Other errors should be reported */
        return error_from_git(git_err);
    }

    /* Open the source git repository */
    git_repository *source_repo = NULL;
    git_err = git_repository_open(&source_repo, discovered_path.ptr);
    if (git_err < 0) {
        git_buf_dispose(&discovered_path);
        return error_from_git(git_err);
    }

    /* Free the discovered path buffer */
    git_buf_dispose(&discovered_path);

    /* Get the repository workdir to make path relative */
    const char *workdir = git_repository_workdir(source_repo);
    if (!workdir) {
        git_repository_free(source_repo);
        /* Bare repo - no workdir, can't have ignored files */
        return NULL;
    }

    /* Make path relative to the source repository workdir */
    const char *rel_path = abs_path;
    size_t workdir_len = strlen(workdir);

    /* Remove workdir prefix if path starts with it */
    if (strncmp(abs_path, workdir, workdir_len) == 0) {
        rel_path = abs_path + workdir_len;
        /* Skip leading slashes */
        while (*rel_path == '/') {
            rel_path++;
        }
    }

    if (*rel_path == '\0') {
        /* Path is the workdir itself */
        git_repository_free(source_repo);
        return NULL;
    }

    /* Check if path is ignored in source repository */
    int ignored = 0;
    git_err = git_ignore_path_is_ignored(&ignored, source_repo, rel_path);

    git_repository_free(source_repo);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    *matched = (ignored == 1);
    return NULL;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

error_t *ignore_context_create(
    git_repository *repo,
    const dotta_config_t *config,
    const char *profile_name,
    const char **cli_excludes,
    size_t cli_exclude_count,
    ignore_context_t **out
) {
    CHECK_NULL(out);

    ignore_context_t *ctx = calloc(1, sizeof(ignore_context_t));
    if (!ctx) {
        return ERROR(ERR_MEMORY, "Failed to allocate ignore context");
    }

    ctx->repo = repo;  /* Borrowed reference */

    /* Copy CLI patterns */
    if (cli_excludes && cli_exclude_count > 0) {
        /* Validate pattern count to prevent overflow and DoS */
        if (cli_exclude_count > MAX_PATTERN_COUNT) {
            free(ctx);
            return ERROR(ERR_VALIDATION, "Too many CLI exclude patterns (max 10000)");
        }

        ctx->cli_patterns = malloc(cli_exclude_count * sizeof(char *));
        if (!ctx->cli_patterns) {
            free(ctx);
            return ERROR(ERR_MEMORY, "Failed to allocate CLI patterns");
        }

        for (size_t i = 0; i < cli_exclude_count; i++) {
            /* Validate pattern length to prevent excessive memory use and DoS */
            if (cli_excludes[i] && strlen(cli_excludes[i]) > MAX_PATTERN_LENGTH) {
                /* Clean up already allocated patterns */
                for (size_t j = 0; j < i; j++) {
                    free(ctx->cli_patterns[j]);
                }
                free(ctx->cli_patterns);
                free(ctx);
                return ERROR(ERR_VALIDATION, "CLI exclude pattern too long (max 4096 chars)");
            }

            ctx->cli_patterns[i] = strdup(cli_excludes[i]);
            if (!ctx->cli_patterns[i]) {
                /* Clean up already allocated patterns */
                for (size_t j = 0; j < i; j++) {
                    free(ctx->cli_patterns[j]);
                }
                free(ctx->cli_patterns);
                free(ctx);
                return ERROR(ERR_MEMORY, "Failed to copy CLI pattern");
            }
        }
        ctx->cli_pattern_count = cli_exclude_count;
    }

    /* Load profile-specific .dottaignore (if profile specified) */
    if (repo && profile_name) {
        error_t *err = load_profile_dottaignore(repo, profile_name, &ctx->profile_dottaignore_content);
        if (err) {
            /* Non-fatal - continue without profile .dottaignore */
            error_free(err);
        }
    }

    /* Load baseline .dottaignore from repository */
    if (repo) {
        error_t *err = load_baseline_dottaignore(repo, &ctx->baseline_dottaignore_content);
        if (err) {
            /* Non-fatal - continue without baseline .dottaignore */
            error_free(err);
        }
    }

    /* Copy config patterns */
    if (config && config->ignore_patterns && config->ignore_pattern_count > 0) {
        /* Validate pattern count to prevent overflow and DoS */
        if (config->ignore_pattern_count > MAX_PATTERN_COUNT) {
            ignore_context_free(ctx);
            return ERROR(ERR_VALIDATION, "Too many config ignore patterns (max 10000)");
        }

        ctx->config_patterns = malloc(config->ignore_pattern_count * sizeof(char *));
        if (!ctx->config_patterns) {
            ignore_context_free(ctx);
            return ERROR(ERR_MEMORY, "Failed to allocate config patterns");
        }

        for (size_t i = 0; i < config->ignore_pattern_count; i++) {
            /* Validate pattern length to prevent excessive memory use and DoS */
            if (config->ignore_patterns[i] && strlen(config->ignore_patterns[i]) > MAX_PATTERN_LENGTH) {
                /* Clean up */
                for (size_t j = 0; j < i; j++) {
                    free(ctx->config_patterns[j]);
                }
                free(ctx->config_patterns);
                ignore_context_free(ctx);
                return ERROR(ERR_VALIDATION, "Config ignore pattern too long (max 4096 chars)");
            }

            ctx->config_patterns[i] = strdup(config->ignore_patterns[i]);
            if (!ctx->config_patterns[i]) {
                /* Clean up */
                for (size_t j = 0; j < i; j++) {
                    free(ctx->config_patterns[j]);
                }
                free(ctx->config_patterns);
                ignore_context_free(ctx);
                return ERROR(ERR_MEMORY, "Failed to copy config pattern");
            }
        }
        ctx->config_pattern_count = config->ignore_pattern_count;
    }

    /* Copy settings */
    ctx->respect_gitignore = config ? config->respect_gitignore : true;

    *out = ctx;
    return NULL;
}

void ignore_context_free(ignore_context_t *ctx) {
    if (!ctx) {
        return;
    }

    /* Free CLI patterns */
    if (ctx->cli_patterns) {
        for (size_t i = 0; i < ctx->cli_pattern_count; i++) {
            free(ctx->cli_patterns[i]);
        }
        free(ctx->cli_patterns);
    }

    /* Free .dottaignore content */
    free(ctx->baseline_dottaignore_content);
    free(ctx->profile_dottaignore_content);

    /* Free config patterns */
    if (ctx->config_patterns) {
        for (size_t i = 0; i < ctx->config_pattern_count; i++) {
            free(ctx->config_patterns[i]);
        }
        free(ctx->config_patterns);
    }

    free(ctx);
}

error_t *ignore_should_ignore(
    ignore_context_t *ctx,
    const char *path,
    bool is_directory,
    bool *ignored
) {
    CHECK_NULL(ctx);
    CHECK_NULL(path);
    CHECK_NULL(ignored);

    *ignored = false;

    /* Store absolute path for source .gitignore checking */
    const char *abs_path = path;

    /* Make path relative for matching (remove leading / if present) */
    const char *rel_path = path;
    while (*rel_path == '/') {
        rel_path++;
    }

    if (*rel_path == '\0') {
        /* Empty path after normalization */
        return NULL;
    }

    /* Layer 1: CLI patterns (highest priority) */
    if (matches_cli_patterns(rel_path, ctx->cli_patterns, ctx->cli_pattern_count)) {
        *ignored = true;
        return NULL;
    }

    /* Layer 2+3: Combined baseline + profile .dottaignore patterns
     *
     * Profile .dottaignore extends baseline .dottaignore (from dotta-worktree).
     * By combining them (baseline first, then profile), profile patterns can use
     * negation (!) to override baseline patterns.
     *
     * Example:
     *   Baseline: *.log          (ignore all logs)
     *   Profile:  !important.log (un-ignore this specific file)
     *   Result:   important.log is NOT ignored
     *
     * This matches git's .gitignore semantics where later patterns override earlier ones.
     */
    if (ctx->baseline_dottaignore_content || ctx->profile_dottaignore_content) {
        bool matched = false;
        error_t *err = NULL;
        char *combined_content = NULL;

        /* Combine baseline + profile if both exist */
        if (ctx->baseline_dottaignore_content && ctx->profile_dottaignore_content) {
            combined_content = str_format("%s\n%s",
                ctx->baseline_dottaignore_content,
                ctx->profile_dottaignore_content);
            if (!combined_content) {
                return ERROR(ERR_MEMORY, "Failed to combine .dottaignore patterns");
            }
            err = matches_dottaignore(
                ctx->repo,
                combined_content,
                rel_path,
                is_directory,
                &matched
            );
            free(combined_content);
        } else if (ctx->profile_dottaignore_content) {
            /* Only profile .dottaignore exists */
            err = matches_dottaignore(
                ctx->repo,
                ctx->profile_dottaignore_content,
                rel_path,
                is_directory,
                &matched
            );
        } else {
            /* Only baseline .dottaignore exists */
            err = matches_dottaignore(
                ctx->repo,
                ctx->baseline_dottaignore_content,
                rel_path,
                is_directory,
                &matched
            );
        }

        if (err) {
            /* Non-fatal - continue without .dottaignore checking */
            error_free(err);
        } else if (matched) {
            *ignored = true;
            return NULL;
        }
    }

    /* Layer 4: Config patterns (user-level rules) */
    if (matches_config_patterns(rel_path, ctx->config_patterns, ctx->config_pattern_count)) {
        *ignored = true;
        return NULL;
    }

    /* Layer 5: Source .gitignore (lowest priority, when enabled) */
    if (ctx->respect_gitignore && abs_path[0] == '/') {
        bool matched = false;
        error_t *err = matches_source_gitignore(abs_path, &matched);
        if (err) {
            /* Non-fatal - continue without source .gitignore checking */
            error_free(err);
        } else if (matched) {
            *ignored = true;
            return NULL;
        }
    }

    *ignored = false;
    return NULL;
}

const char *ignore_default_dottaignore_content(void) {
    return DEFAULT_DOTTAIGNORE;
}

const char *ignore_profile_dottaignore_template(void) {
    return PROFILE_DOTTAIGNORE;
}

/**
 * Test path with diagnostic information
 *
 * Similar to ignore_should_ignore() but returns which layer matched.
 */
error_t *ignore_test_path(
    ignore_context_t *ctx,
    const char *path,
    bool is_directory,
    ignore_test_result_t *result
) {
    CHECK_NULL(ctx);
    CHECK_NULL(path);
    CHECK_NULL(result);

    /* Initialize result */
    result->ignored = false;
    result->source = IGNORE_SOURCE_NONE;

    /* Store absolute path for source .gitignore checking */
    const char *abs_path = path;

    /* Make path relative for matching (remove leading / if present) */
    const char *rel_path = path;
    while (*rel_path == '/') {
        rel_path++;
    }

    if (*rel_path == '\0') {
        /* Empty path after normalization */
        return NULL;
    }

    /* Layer 1: CLI patterns (highest priority) */
    if (matches_cli_patterns(rel_path, ctx->cli_patterns, ctx->cli_pattern_count)) {
        result->ignored = true;
        result->source = IGNORE_SOURCE_CLI;
        return NULL;
    }

    /* Layer 2+3: Combined baseline + profile .dottaignore patterns
     *
     * Profile .dottaignore extends baseline .dottaignore (from dotta-worktree).
     * By combining them (baseline first, then profile), profile patterns can use
     * negation (!) to override baseline patterns.
     */
    if (ctx->baseline_dottaignore_content || ctx->profile_dottaignore_content) {
        bool matched = false;
        error_t *err = NULL;
        char *combined_content = NULL;
        ignore_source_t source = IGNORE_SOURCE_NONE;

        /* Combine baseline + profile if both exist */
        if (ctx->baseline_dottaignore_content && ctx->profile_dottaignore_content) {
            combined_content = str_format("%s\n%s",
                ctx->baseline_dottaignore_content,
                ctx->profile_dottaignore_content);
            if (!combined_content) {
                return ERROR(ERR_MEMORY, "Failed to combine .dottaignore patterns");
            }
            err = matches_dottaignore(
                ctx->repo,
                combined_content,
                rel_path,
                is_directory,
                &matched
            );
            free(combined_content);
            /* When combined, attribute to profile (it has final say via negation) */
            source = IGNORE_SOURCE_PROFILE_DOTTAIGNORE;
        } else if (ctx->profile_dottaignore_content) {
            /* Only profile .dottaignore exists */
            err = matches_dottaignore(
                ctx->repo,
                ctx->profile_dottaignore_content,
                rel_path,
                is_directory,
                &matched
            );
            source = IGNORE_SOURCE_PROFILE_DOTTAIGNORE;
        } else {
            /* Only baseline .dottaignore exists */
            err = matches_dottaignore(
                ctx->repo,
                ctx->baseline_dottaignore_content,
                rel_path,
                is_directory,
                &matched
            );
            source = IGNORE_SOURCE_BASELINE_DOTTAIGNORE;
        }

        if (err) {
            /* Non-fatal - continue without .dottaignore checking */
            error_free(err);
        } else if (matched) {
            result->ignored = true;
            result->source = source;
            return NULL;
        }
    }

    /* Layer 4: Config patterns (user-level rules) */
    if (matches_config_patterns(rel_path, ctx->config_patterns, ctx->config_pattern_count)) {
        result->ignored = true;
        result->source = IGNORE_SOURCE_CONFIG;
        return NULL;
    }

    /* Layer 5: Source .gitignore (lowest priority, when enabled) */
    if (ctx->respect_gitignore && abs_path[0] == '/') {
        bool matched = false;
        error_t *err = matches_source_gitignore(abs_path, &matched);
        if (err) {
            /* Non-fatal - continue without source .gitignore checking */
            error_free(err);
        } else if (matched) {
            result->ignored = true;
            result->source = IGNORE_SOURCE_SOURCE_GITIGNORE;
            return NULL;
        }
    }

    /* Not ignored */
    result->ignored = false;
    result->source = IGNORE_SOURCE_NONE;
    return NULL;
}

/**
 * Convert ignore source to human-readable string
 */
const char *ignore_source_to_string(ignore_source_t source) {
    switch (source) {
        case IGNORE_SOURCE_NONE:
            return "not ignored";
        case IGNORE_SOURCE_CLI:
            return "CLI --exclude patterns";
        case IGNORE_SOURCE_PROFILE_DOTTAIGNORE:
            return "profile .dottaignore";
        case IGNORE_SOURCE_BASELINE_DOTTAIGNORE:
            return "baseline .dottaignore";
        case IGNORE_SOURCE_CONFIG:
            return "config file patterns";
        case IGNORE_SOURCE_SOURCE_GITIGNORE:
            return "source .gitignore";
        default:
            return "unknown";
    }
}
