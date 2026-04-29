/**
 * ignore.c - Layered `.dottaignore` ruleset builder and persistence.
 *
 * The builder pre-loads the three "common" layers (baseline or
 * builtin, config patterns, CLI excludes) into an arena at creation
 * time, and lazily assembles a fresh per-profile ruleset on first
 * call to `ignore_rules_for_profile`. Subsequent calls with the same
 * profile name return the cached pointer — memoisation lives in the
 * builder, not in any caller bookkeeping.
 *
 * Why re-append common layers instead of sharing one base ruleset:
 * `base/gitignore` rulesets are append-only values in an arena.
 * Composing a base + profile cheaply across multiple profiles would
 * need a clone primitive in the engine. Re-appending from the saved
 * sources (static `DEFAULT_DOTTAIGNORE` string, Git-loaded baseline
 * content, caller-borrowed config and CLI arrays) parses each input
 * once per profile for a few-hundred-byte cost; trivial next to the
 * SQLite + Git work the surrounding commands do. Option kept on the
 * shelf: if someone ever profiles this as hot, add a `clone_into`
 * to the engine and short-circuit.
 *
 * Source-tree `.gitignore` (a foreign repo the user is adding files
 * from) is a separate mechanism — see `sys/source.h`. Consumers
 * compose the two explicitly.
 */

#include "core/ignore.h"

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/string.h"
#include "infra/worktree.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

/* Size cap on `.dottaignore` blobs — an ignore-specific policy
 * guarding against a runaway file pulled in from Git. The underlying
 * gitignore engine already caps per-pattern length and rule count.
 * Typed as size_t so the multiplication happens in size_t and the
 * comparison against blob sizes stays warning-clean. */
#define MAX_DOTTAIGNORE_SIZE ((size_t) 1024 * 1024)   /* 1 MB */

/* Initial profile-cache capacity. Profile counts are almost always
 * single-digit so the cache rarely grows. */
#define INITIAL_PROFILE_CAPACITY 4

/**
 * Default baseline `.dottaignore` content.
 *
 * Seeded into new repos by `dotta init` / `dotta clone`, and used as
 * the BUILTIN fallback whenever the baseline blob is absent so safety
 * patterns stay active regardless of repo state.
 */
static const char *const DEFAULT_DOTTAIGNORE =
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
 * Minimal `.dottaignore` template for new profiles.
 */
static const char *const PROFILE_DOTTAIGNORE =
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

/**
 * One entry in the profile-ruleset memoisation table.
 *
 * `name` is the canonicalised key (empty string "" stands for the
 * baseline-only ruleset — NULL and "" collapse to the same entry).
 */
typedef struct {
    const char *name;
    gitignore_ruleset_t *ruleset;
} profile_entry_t;

struct ignore_rules {
    arena_t *arena;                 /* borrowed; backs baseline copy, cache array, all rulesets */
    git_repository *repo;           /* borrowed; used only by lazy profile loads */

    /* Common layers. `baseline_content` is either an arena-owned copy
     * of the Git blob (origin=BASELINE) or a pointer to the static
     * DEFAULT_DOTTAIGNORE string (origin=BUILTIN). Either is valid for
     * the builder's lifetime. */
    const char *baseline_content;
    ignore_origin_t baseline_origin;

    /* Borrowed pattern arrays. Callers guarantee they outlive the
     * builder (command-scoped config and CLI). */
    char *const *config_patterns;
    size_t config_count;
    char *const *cli_patterns;
    size_t cli_count;

    /* Memoised per-profile rulesets. Linear scan — profile counts are
     * small (typical <= 5, hard cap at the scope of an enabled set). */
    profile_entry_t *profiles;
    size_t profile_count;
    size_t profile_capacity;
};

/**
 * Grow the profile cache array if we're at capacity.
 *
 * Arena allocators have no in-place realloc, so growth allocates a
 * larger block and copies. The old block is reclaimed on
 * arena_destroy. Mirrors the pattern in base/gitignore.c.
 */
static error_t *profile_cache_ensure_capacity(ignore_rules_t *r) {
    if (r->profile_count < r->profile_capacity) return NULL;

    size_t new_cap = r->profile_capacity
        ? r->profile_capacity * 2
        : INITIAL_PROFILE_CAPACITY;

    profile_entry_t *resized = arena_alloc(
        r->arena, new_cap * sizeof(*resized)
    );
    if (!resized) {
        return ERROR(ERR_MEMORY, "ignore: profile cache allocation failed");
    }
    if (r->profile_count > 0) {
        memcpy(resized, r->profiles, r->profile_count * sizeof(*resized));
    }
    r->profiles = resized;
    r->profile_capacity = new_cap;
    return NULL;
}

/**
 * Build a fresh ruleset for `profile` in the builder's arena.
 *
 * Appends the four layers in precedence order (baseline/builtin,
 * profile, config, CLI). `gitignore_eval` scans in reverse insertion
 * order, so CLI wins last-match and the ordering here establishes
 * the documented precedence for free.
 *
 * `profile` is the canonicalised key ("" means baseline-only).
 */
static error_t *build_profile_ruleset(
    ignore_rules_t *r,
    const char *profile,
    gitignore_ruleset_t **out
) {
    gitignore_ruleset_t *rs = NULL;
    RETURN_IF_ERROR(gitignore_ruleset_create(r->arena, &rs));

    /* 1. Baseline / builtin fallback (lowest precedence). */
    RETURN_IF_ERROR(
        gitignore_ruleset_append(
        rs,
        r->baseline_content,
        (gitignore_origin_t) r->baseline_origin
        )
    );

    /* 2. Profile-specific `.dottaignore` (if the profile was named and
     *    has a blob on its branch). A missing branch / missing file /
     *    empty blob is normal and silently contributes no rules. */
    if (profile[0] != '\0') {
        char *content = NULL;
        error_t *err = ignore_blob_read(r->repo, profile, &content, NULL);
        if (err) {
            return error_wrap(
                err, "Failed to load .dottaignore for profile '%s'", profile
            );
        }
        if (content) {
            err = gitignore_ruleset_append(
                rs, content, (gitignore_origin_t) IGNORE_ORIGIN_PROFILE
            );
            free(content);
            if (err) {
                return error_wrap(
                    err, "Failed to parse .dottaignore for profile '%s'",
                    profile
                );
            }
        }
    }

    /* 3. Config patterns. */
    if (r->config_count > 0) {
        RETURN_IF_ERROR(
            gitignore_ruleset_append_patterns(
            rs,
            (const char *const *) r->config_patterns,
            r->config_count,
            (gitignore_origin_t) IGNORE_ORIGIN_CONFIG
            )
        );
    }

    /* 4. CLI excludes — highest precedence, appended last. */
    if (r->cli_count > 0) {
        RETURN_IF_ERROR(
            gitignore_ruleset_append_patterns(
            rs,
            (const char *const *) r->cli_patterns,
            r->cli_count,
            (gitignore_origin_t) IGNORE_ORIGIN_CLI
            )
        );
    }

    *out = rs;
    return NULL;
}

error_t *ignore_blob_read(
    git_repository *repo,
    const char *branch,
    char **out_content,
    size_t *out_size
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch);
    CHECK_NULL(out_content);
    CHECK_ARG(branch[0] != '\0', "Branch name cannot be empty");

    *out_content = NULL;
    if (out_size) *out_size = 0;

    /* Missing branch is not an error — callers treat NULL content as
     * "no baseline/profile .dottaignore yet". */
    bool exists = false;
    RETURN_IF_ERROR(gitops_branch_exists(repo, branch, &exists));
    if (!exists) return NULL;

    /* Existence just verified, so a tree load failure is a real error
     * (I/O, corruption) rather than "branch missing". */
    git_tree *tree = NULL;
    error_t *err = gitops_load_branch_tree(repo, branch, &tree, NULL);
    if (err) {
        return error_wrap(err, "Failed to load tree for branch '%s'", branch);
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
            ".dottaignore on branch '%s' exceeds capacity "
            "(max %zu bytes, actual %zu)",
            branch, (size_t) MAX_DOTTAIGNORE_SIZE, size
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

error_t *ignore_blob_write(
    git_repository *repo,
    const char *branch,
    const char *content,
    size_t size,
    const char *commit_msg
) {
    CHECK_NULL(repo);
    CHECK_NULL(branch);
    CHECK_NULL(content);
    CHECK_NULL(commit_msg);
    CHECK_ARG(branch[0] != '\0', "Branch name cannot be empty");

    if (size > MAX_DOTTAIGNORE_SIZE) {
        return ERROR(
            ERR_VALIDATION,
            ".dottaignore content exceeds capacity "
            "(max %zu bytes, actual %zu)",
            (size_t) MAX_DOTTAIGNORE_SIZE, size
        );
    }

    return gitops_update_file(
        repo, branch, ".dottaignore", content, size,
        commit_msg, GIT_FILEMODE_BLOB, NULL
    );
}

error_t *ignore_rules_create(
    git_repository *repo,
    const config_t *config,
    char *const *cli_excludes,
    size_t cli_count,
    arena_t *arena,
    ignore_rules_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    ignore_rules_t *r = calloc(1, sizeof(*r));
    if (!r) {
        return ERROR(ERR_MEMORY, "Failed to allocate ignore rules builder");
    }

    r->arena = arena;
    r->repo = repo;

    /* Load baseline; fall back to compiled defaults when absent.
     *
     * Load errors are fatal: a corrupted or unreadable baseline must
     * surface, not silently drop safety defaults. The BUILTIN fallback
     * only fires when the load returned NULL content (branch missing,
     * file missing, or empty blob — all non-errors). */
    char *baseline = NULL;
    error_t *err = ignore_blob_read(repo, "dotta-worktree", &baseline, NULL);
    if (err) {
        ignore_rules_free(r);
        return error_wrap(err, "Failed to load baseline .dottaignore");
    }

    if (baseline) {
        /* Arena-copy so the Git heap buffer can be freed immediately
         * and the content outlives the function frame. */
        r->baseline_content = arena_strdup(r->arena, baseline);
        free(baseline);
        if (!r->baseline_content) {
            ignore_rules_free(r);
            return ERROR(ERR_MEMORY, "Failed to copy baseline content");
        }
        r->baseline_origin = IGNORE_ORIGIN_BASELINE;
    } else {
        /* Static string — no copy needed; always valid. */
        r->baseline_content = DEFAULT_DOTTAIGNORE;
        r->baseline_origin = IGNORE_ORIGIN_BUILTIN;
    }

    /* Borrow config/CLI arrays. The caller guarantees command-scoped
     * lifetime, which is longer than the builder's. */
    if (config && config->ignore_patterns &&
        config->ignore_pattern_count > 0) {
        r->config_patterns = config->ignore_patterns;
        r->config_count = config->ignore_pattern_count;
    }
    if (cli_excludes && cli_count > 0) {
        r->cli_patterns = cli_excludes;
        r->cli_count = cli_count;
    }

    *out = r;
    return NULL;
}

void ignore_rules_free(ignore_rules_t *r) {
    if (!r) return;

    /* Arena is borrowed — owned by the caller (typically ctx->arena).
     * Per-profile rulesets, baseline copies, and the profile cache
     * remain valid in that arena until the caller destroys it. */
    free(r);
}

error_t *ignore_rules_for_profile(
    ignore_rules_t *r,
    const char *profile,
    const gitignore_ruleset_t **out
) {
    CHECK_NULL(r);
    CHECK_NULL(out);

    *out = NULL;

    /* Canonicalise NULL/empty to "" so both cases share a cache slot. */
    const char *key = (profile && profile[0]) ? profile : "";

    /* Memoisation lookup. */
    for (size_t i = 0; i < r->profile_count; i++) {
        if (strcmp(r->profiles[i].name, key) == 0) {
            *out = r->profiles[i].ruleset;
            return NULL;
        }
    }

    /* Build fresh and cache. */
    gitignore_ruleset_t *rs = NULL;
    RETURN_IF_ERROR(build_profile_ruleset(r, key, &rs));

    RETURN_IF_ERROR(profile_cache_ensure_capacity(r));

    const char *name_copy = arena_strdup(r->arena, key);
    if (!name_copy) {
        return ERROR(ERR_MEMORY, "Failed to copy profile name");
    }
    r->profiles[r->profile_count].name = name_copy;
    r->profiles[r->profile_count].ruleset = rs;
    r->profile_count++;

    *out = rs;
    return NULL;
}

const char *ignore_origin_describe(ignore_origin_t origin) {
    switch (origin) {
        case IGNORE_ORIGIN_NONE:     return "not ignored";
        case IGNORE_ORIGIN_BUILTIN:  return "built-in defaults";
        case IGNORE_ORIGIN_BASELINE: return "baseline .dottaignore";
        case IGNORE_ORIGIN_PROFILE:  return "profile .dottaignore";
        case IGNORE_ORIGIN_CONFIG:   return "config file patterns";
        case IGNORE_ORIGIN_CLI:      return "CLI --exclude patterns";
    }
    return "unknown";
}

const char *ignore_baseline_defaults(void) {
    return DEFAULT_DOTTAIGNORE;
}

const char *ignore_profile_template(void) {
    return PROFILE_DOTTAIGNORE;
}

error_t *ignore_seed_baseline(git_repository *repo) {
    CHECK_NULL(repo);

    return ignore_blob_write(
        repo, "dotta-worktree",
        DEFAULT_DOTTAIGNORE,
        strlen(DEFAULT_DOTTAIGNORE),
        "Initialize .dottaignore with default patterns"
    );
}

error_t *ignore_seed_profile(worktree_handle_t *wt) {
    CHECK_NULL(wt);

    const char *wt_path = worktree_get_path(wt);
    if (!wt_path) {
        return ERROR(ERR_INTERNAL, "Worktree path is NULL");
    }

    char *path = str_format("%s/.dottaignore", wt_path);
    if (!path) {
        return ERROR(ERR_MEMORY, "Failed to allocate .dottaignore path");
    }

    buffer_t content = BUFFER_INIT;
    error_t *err = buffer_append_string(&content, PROFILE_DOTTAIGNORE);
    if (err) {
        buffer_free(&content);
        free(path);
        return error_wrap(err, "Failed to populate .dottaignore buffer");
    }

    err = fs_write_file(path, &content);
    buffer_free(&content);
    free(path);
    if (err) return error_wrap(err, "Failed to write .dottaignore");

    err = worktree_stage_file(wt, ".dottaignore");
    if (err) return error_wrap(err, "Failed to stage .dottaignore");

    return NULL;
}
