/**
 * ignore.c - Multi-layered ignore pattern system implementation
 *
 * All user-authored ignore rules (baseline/builtin defaults, profile
 * .dottaignore, config patterns, CLI excludes) compile into a single
 * gitignore_ruleset_t at context creation. Rules are appended in
 * precedence order (baseline first, CLI last); gitignore_eval's
 * last-match-wins semantics give the right verdict for free, including
 * cross-layer negation (e.g. baseline `*.log` + profile `!debug.log`).
 *
 * Source-tree `.gitignore` — the rules of a foreign git repo the user
 * is adding files from — is a separate mechanism in `sys/source.h`.
 * Callers compose the two explicitly.
 */

#include "core/ignore.h"

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "sys/gitops.h"

/* Input validation limits.
 *
 * Per-pattern length and cumulative rule count are enforced by the
 * underlying gitignore engine (see base/gitignore.c); they are
 * intentionally not duplicated here. Only the blob-size cap — an
 * ignore-specific policy that guards against a runaway .dottaignore
 * file pulled in from Git — lives in this module. */
#define MAX_DOTTAIGNORE_SIZE (1024 * 1024)   /* 1MB per .dottaignore blob */

/* Initial arena block. Comfortably fits a typical baseline (~1KB)
 * plus a handful of extra rules; the arena grows on demand. */
#define IGNORE_ARENA_INITIAL_CAPACITY (8 * 1024)

/**
 * Ignore context — arena-backed compiled ruleset.
 *
 * Rules compile into a single gitignore_ruleset_t at creation. Matching
 * is pure in-memory evaluation; no mutation of the dotta repository
 * handle occurs. Multiple contexts against the same repo are safe and
 * independent.
 */
struct ignore_context {
    arena_t *arena;                     /* owns ruleset + pattern copies */
    gitignore_ruleset_t *ruleset;       /* baseline/builtin + profile + config + CLI */
};

/**
 * Default baseline .dottaignore content.
 *
 * Seeded into new repos by `dotta init` / `dotta clone`, and applied
 * as origin=BUILTIN fallback whenever the baseline is absent so safety
 * patterns stay active regardless of repo state.
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
 * Minimal .dottaignore template for new profiles.
 *
 * Provides a clean starting point with documentation about the layering
 * system. Users can add profile-specific patterns or use negation (!)
 * to override baseline rules.
 */
static const char *PROFILE_DOTTAIGNORE =
    "# Dotta Ignore Patterns\n"
    "#\n"
    "# This profile's ignore patterns work in layers (in precedence order):\n"
    "#   1. CLI --exclude flags (highest priority - per-operation)\n"
    "#   2. Combined .dottaignore (baseline + this file, evaluated together):\n"
    "#      - Baseline .dottaignore (from dotta-worktree, applies to all profiles)\n"
    "#      - Profile .dottaignore (this file - later rules override baseline)\n"
    "#   3. Config file patterns (from ~/.config/dotta/config.toml)\n"
    "#   4. Source .gitignore (lowest priority - when adding from git repos)\n"
    "#\n"
    "# Important: This profile automatically inherits all baseline patterns.\n"
    "# Use negation patterns (!) to override baseline. Example:\n"
    "#   Baseline has: *.log\n"
    "#   Profile adds: !important.log\n"
    "#   Result: important.log is not ignored in this profile\n"
    "#\n"
    "# This file uses standard .gitignore syntax:\n"
    "#   - Use # for comments\n"
    "#   - Use * ? [abc] for glob patterns\n"
    "#   - Use / at end to match only directories\n"
    "#   - Use ! to negate a pattern (override baseline)\n"
    "#   - Use / at start to anchor to repo root\n"
    "\n"
    "# Add your profile-specific patterns below:\n";

error_t *ignore_load_raw_content(
    git_repository *repo,
    const char *branch_name,
    char **out_content,
    size_t *out_size
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch_name);
    CHECK_NULL(out_content);
    CHECK_ARG(branch_name[0] != '\0', "Branch name cannot be empty");

    *out_content = NULL;
    if (out_size) *out_size = 0;

    /* Missing branch is not an error — callers treat NULL content as
     * "no baseline/profile .dottaignore yet". */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, branch_name, &branch_exists);
    if (err) return err;
    if (!branch_exists) return NULL;

    /* Existence just verified, so a tree load failure is a real error
     * (I/O, corruption) rather than "branch missing". */
    git_tree *tree = NULL;
    err = gitops_load_branch_tree(repo, branch_name, &tree, NULL);
    if (err) {
        return error_wrap(
            err, "Failed to load tree for branch '%s'", branch_name
        );
    }

    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (!entry) {
        git_tree_free(tree);
        return NULL;
    }

    void *content = NULL;
    size_t size = 0;
    err = gitops_read_blob_content(
        repo, git_tree_entry_id(entry), &content, &size
    );
    git_tree_free(tree);
    if (err) return err;

    if (size > MAX_DOTTAIGNORE_SIZE) {
        free(content);
        return ERROR(
            ERR_VALIDATION,
            ".dottaignore on branch '%s' exceeds capacity (max %d bytes, actual %zu)",
            branch_name, MAX_DOTTAIGNORE_SIZE, size
        );
    }

    /* Treat empty blobs as absent — nothing to parse, and it lets
     * callers use "content == NULL" as the single "no source" check. */
    if (size == 0) {
        free(content);
        return NULL;
    }

    *out_content = content;
    if (out_size) *out_size = size;
    return NULL;
}

error_t *ignore_context_create(
    git_repository *repo,
    const config_t *config,
    const char *profile,
    char **cli_excludes,
    size_t cli_exclude_count,
    ignore_context_t **out
) {
    CHECK_NULL(out);

    *out = NULL;

    ignore_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return ERROR(ERR_MEMORY, "Failed to allocate ignore context");
    }

    ctx->arena = arena_create(IGNORE_ARENA_INITIAL_CAPACITY);
    if (!ctx->arena) {
        free(ctx);
        return ERROR(ERR_MEMORY, "Failed to allocate ignore arena");
    }

    error_t *err = gitignore_ruleset_create(ctx->arena, &ctx->ruleset);
    if (err) {
        ignore_context_free(ctx);
        return err;
    }

    /* Build the ruleset in precedence order (lowest first, highest last).
     * gitignore_eval scans in reverse insertion order, so the tail wins
     * on overlapping matches:
     *   1. baseline / builtin fallback  (lowest precedence)
     *   2. profile .dottaignore
     *   3. config patterns
     *   4. CLI --exclude flags          (highest precedence)
     */

    /* 1. Baseline .dottaignore, or compiled defaults as fallback.
     *
     * Load errors are fatal: a corrupted or unreadable .dottaignore
     * must surface, not silently drop safety defaults. The BUILTIN
     * fallback only fires when the load returned NULL content (branch
     * missing, file missing, or empty blob — all non-errors). */
    if (repo) {
        char *baseline_content = NULL;
        err = ignore_load_raw_content(
            repo, "dotta-worktree", &baseline_content, NULL
        );
        if (err) {
            ignore_context_free(ctx);
            return error_wrap(err, "Failed to load baseline .dottaignore");
        }

        if (baseline_content) {
            err = gitignore_ruleset_append(
                ctx->ruleset,
                baseline_content,
                (gitignore_origin_t) IGNORE_SOURCE_BASELINE_DOTTAIGNORE
            );
            free(baseline_content);
            if (err) {
                ignore_context_free(ctx);
                return error_wrap(err, "Failed to parse baseline .dottaignore");
            }
        } else {
            err = gitignore_ruleset_append(
                ctx->ruleset,
                DEFAULT_DOTTAIGNORE,
                (gitignore_origin_t) IGNORE_SOURCE_BUILTIN
            );
            if (err) {
                ignore_context_free(ctx);
                return err;
            }
        }
    } else {
        /* No repo handle — apply builtin defaults so safety patterns
         * still fire (e.g., callers testing patterns without an open repo). */
        err = gitignore_ruleset_append(
            ctx->ruleset,
            DEFAULT_DOTTAIGNORE,
            (gitignore_origin_t) IGNORE_SOURCE_BUILTIN
        );
        if (err) {
            ignore_context_free(ctx);
            return err;
        }
    }

    /* 2. Profile .dottaignore (if specified and present). Fatal on
     * load or parse error, same rationale as baseline. */
    if (repo && profile && profile[0] != '\0') {
        char *profile_content = NULL;
        err = ignore_load_raw_content(
            repo, profile, &profile_content, NULL
        );
        if (err) {
            ignore_context_free(ctx);
            return error_wrap(
                err, "Failed to load .dottaignore for profile '%s'", profile
            );
        }

        if (profile_content) {
            err = gitignore_ruleset_append(
                ctx->ruleset,
                profile_content,
                (gitignore_origin_t) IGNORE_SOURCE_PROFILE_DOTTAIGNORE
            );
            free(profile_content);
            if (err) {
                ignore_context_free(ctx);
                return error_wrap(
                    err, "Failed to parse .dottaignore for profile '%s'", profile
                );
            }
        }
    }

    /* 3. Config patterns. */
    if (config && config->ignore_patterns && config->ignore_pattern_count > 0) {
        err = gitignore_ruleset_append_patterns(
            ctx->ruleset,
            (const char *const *) config->ignore_patterns,
            config->ignore_pattern_count,
            (gitignore_origin_t) IGNORE_SOURCE_CONFIG
        );
        if (err) {
            ignore_context_free(ctx);
            return error_wrap(err, "Failed to compile config ignore patterns");
        }
    }

    /* 4. CLI excludes — appended last so they win last-match. */
    if (cli_excludes && cli_exclude_count > 0) {
        err = gitignore_ruleset_append_patterns(
            ctx->ruleset,
            (const char *const *) cli_excludes,
            cli_exclude_count,
            (gitignore_origin_t) IGNORE_SOURCE_CLI
        );
        if (err) {
            ignore_context_free(ctx);
            return error_wrap(err, "Failed to compile CLI exclude patterns");
        }
    }

    *out = ctx;
    return NULL;
}

void ignore_context_free(ignore_context_t *ctx) {
    if (!ctx) return;

    /* Arena destroy frees the ruleset and every pattern copy in one go.
     * arena_destroy(NULL) is a no-op — safe for partial-state contexts
     * (e.g., allocation failure mid-create). */
    arena_destroy(ctx->arena);

    free(ctx);
}

error_t *ignore_test_path(
    ignore_context_t *ctx,
    const char *path,
    bool is_directory,
    ignore_test_result_t *result
) {
    CHECK_NULL(ctx);
    CHECK_NULL(path);
    CHECK_NULL(result);

    result->ignored = false;
    result->source = IGNORE_SOURCE_NONE;

    /* Evaluate the compiled ruleset. gitignore_eval scans in reverse
     * insertion order (CLI → config → profile → baseline); the first
     * match decides. match.origin exposes the winning source verbatim. */
    gitignore_match_t match;
    gitignore_eval(ctx->ruleset, path, is_directory, &match);
    if (match.decided && match.ignored) {
        result->ignored = true;
        result->source = (ignore_source_t) match.origin;
    }

    return NULL;
}

error_t *ignore_should_ignore(
    ignore_context_t *ctx,
    const char *path,
    bool is_directory,
    bool *ignored
) {
    CHECK_NULL(ignored);

    ignore_test_result_t result;
    error_t *err = ignore_test_path(ctx, path, is_directory, &result);
    if (err) return err;

    *ignored = result.ignored;
    return NULL;
}

const char *ignore_default_dottaignore_content(void) {
    return DEFAULT_DOTTAIGNORE;
}

const char *ignore_profile_dottaignore_template(void) {
    return PROFILE_DOTTAIGNORE;
}

error_t *ignore_seed_baseline(git_repository *repo) {
    CHECK_NULL(repo);

    const char *content = DEFAULT_DOTTAIGNORE;
    return gitops_update_file(
        repo,
        "dotta-worktree",
        ".dottaignore",
        content,
        strlen(content),
        "Initialize .dottaignore with default patterns",
        GIT_FILEMODE_BLOB,
        NULL
    );
}

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
        case IGNORE_SOURCE_BUILTIN:
            return "built-in defaults";
        case IGNORE_SOURCE_CONFIG:
            return "config file patterns";
        default:
            return "unknown";
    }
}
