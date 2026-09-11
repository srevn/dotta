/**
 * ignore.c - Layered `.dottaignore` ruleset builder and persistence.
 *
 * The builder holds the layers every profile shares — the baseline, compiled at
 * creation; the config's, compiled at load (utils/config) and borrowed; the CLI
 * layer, compiled once by ignore_excludes_compile and handed in — and lazily
 * assembles a fresh per-profile ruleset on first call to
 * `ignore_rules_for_profile`. Subsequent calls with the same profile name return
 * the cached pointer — memoisation lives in the builder, not in any caller
 * bookkeeping.
 *
 * A compiled layer is composed by copying (gitignore_ruleset_append_rules): each
 * per-profile ruleset copies the baseline's, the config's and the CLI's rules
 * around the profile's own .dottaignore and borrows their strings, so what was
 * read once is not read again. The layers make one ruleset, not four verdicts:
 * a later layer's `!` has to be asked at the same rung as the earlier layer's
 * directory it re-opens (ignore.h).
 *
 * Source-tree `.gitignore` (a foreign repo the user is adding files from) is a
 * separate mechanism — see `sys/source.h`. Consumers compose the two explicitly.
 */

#include "core/ignore.h"

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "sys/gitops.h"
#include "sys/stage.h"

/* Size cap on `.dottaignore` blobs — an ignore-specific policy guarding against
 * a runaway file pulled in from Git. The underlying gitignore engine already
 * caps per-pattern length and rule count. Typed as size_t so the multiplication
 * happens in size_t and the comparison against blob sizes stays warning-clean. */
#define MAX_DOTTAIGNORE_SIZE ((size_t) 1024 * 1024)   /* 1 MB */

/* Initial profile-cache capacity. Profile counts are almost always single-digit
 * so the cache rarely grows. */
#define INITIAL_PROFILE_CAPACITY 4

/**
 * Default baseline `.dottaignore` content.
 *
 * Seeded into new repos by `dotta init` / `dotta clone`, and used as the BUILTIN
 * fallback whenever the baseline blob is absent so safety patterns stay active
 * regardless of repo state.
 */
static const char *const DEFAULT_DOTTAIGNORE =
    "# Dotta Ignore Patterns\n"
    "#\n"
    "# Patterns are matched against the path relative to its mount root, as a\n"
    "# .gitignore at ~ (home/ files), at / (root/ files) or at the deployment\n"
    "# target (custom/ files) would match it: `.config/Code/Cache/` is\n"
    "# ~/.config/Code/Cache, never spelled with the home/ label.\n"
    "#\n"
    "# This file uses .gitignore syntax:\n"
    "#   - Use # for comments\n"
    "#   - Use * ? [abc] for glob patterns\n"
    "#   - Use / at end to match only directories\n"
    "#   - Use ! to negate a pattern. A ! cannot re-open a directory an\n"
    "#     earlier pattern excluded: with `.cache/` above it, `!.cache/keep`\n"
    "#     does nothing and `!.cache/` is what re-opens it\n"
    "#   - Use / at start to anchor to the mount root (`/.cache/` is ~/.cache\n"
    "#     alone; `.cache/` is every .cache directory)\n"
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
    "#   2. Config file patterns (from ~/.config/dotta/config.toml)\n"
    "#   3. Combined .dottaignore (baseline + this file, evaluated together):\n"
    "#      - Profile .dottaignore (this file - later rules override baseline)\n"
    "#      - Baseline .dottaignore (this machine's, applies to all profiles)\n"
    "#   4. Source .gitignore (lowest priority - when adding from git repos)\n"
    "#\n"
    "# Patterns are matched against the path relative to its mount root, as a\n"
    "# .gitignore at ~ (home/ files), at / (root/ files) or at the deployment\n"
    "# target (custom/ files) would match it: `.config/Code/Cache/` is\n"
    "# ~/.config/Code/Cache, never spelled with the home/ label.\n"
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
    "#   - Use / at start to anchor to the mount root (`/.cache/` is ~/.cache\n"
    "#     alone; `.cache/` is every .cache directory)\n"
    "\n"
    "# Add your profile-specific patterns below:\n";

/* One entry in the per-profile memo (ignore_rules_for_profile) */
typedef struct {
    const char *name;             /* the key; "" for baseline-only */
    gitignore_ruleset_t *ruleset;
} profile_entry_t;

struct ignore_rules {
    arena_t *arena;                            /* borrowed; backs all of it */
    git_repository *repo;                      /* borrowed; profile blobs */

    /* The layers every profile shares (ignore_rules_create) */
    const gitignore_ruleset_t *baseline_rules; /* compiled at creation */
    ignore_origin_t baseline_origin;           /* BASELINE, or BUILTIN */
    const gitignore_ruleset_t *config_rules;   /* borrowed; compiled at load */
    const gitignore_ruleset_t *cli_rules;      /* borrowed; NULL when no -e */

    /* Memoised per-profile rulesets: a linear scan, as profiles are few */
    profile_entry_t *profiles;
    size_t profile_count;
    size_t profile_capacity;
};

/**
 * Grow the profile cache array if we're at capacity.
 *
 * Arena allocators have no in-place realloc, so growth allocates a larger block
 * and copies. The old block is reclaimed on arena_destroy.
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
 * Appends the four layers in precedence order (baseline/builtin, profile, config,
 * CLI) — the baseline's, the config's and the CLI's compiled rules copied, the
 * profile's .dottaignore read. `gitignore_eval` scans in reverse insertion order,
 * so CLI wins last-match and the ordering here establishes the documented
 * precedence for free.
 *
 * `profile` is the canonicalised key ("" means baseline-only).
 */
static error_t *build_profile_ruleset(
    ignore_rules_t *r, const char *profile, gitignore_ruleset_t **out
) {
    gitignore_ruleset_t *rs = NULL;
    RETURN_IF_ERROR(gitignore_ruleset_create(r->arena, &rs));

    /* 1. Baseline / builtin fallback (lowest precedence). */
    RETURN_IF_ERROR(
        gitignore_ruleset_append_rules(
        rs, r->baseline_rules, (gitignore_origin_t) r->baseline_origin
        )
    );

    /* 2. Profile-specific `.dottaignore` (if the profile was named and has a
     *    blob on its branch). A missing branch / missing file / empty blob is
     *    normal and silently contributes no rules. */
    if (profile[0] != '\0') {
        char refname[DOTTA_REFNAME_MAX];
        RETURN_IF_ERROR(gitops_branch_refname(refname, sizeof(refname), profile));

        char *content = NULL;
        error_t *err = ignore_blob_text(r->repo, refname, &content);
        if (err) {
            return error_wrap(
                err, "Failed to load .dottaignore for profile '%s'", profile
            );
        }
        if (content) {
            err = gitignore_ruleset_append_file(
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

    /* 3. The config's patterns, compiled at load. */
    RETURN_IF_ERROR(
        gitignore_ruleset_append_rules(
        rs, r->config_rules, (gitignore_origin_t) IGNORE_ORIGIN_CONFIG
        )
    );

    /* 4. CLI excludes — highest precedence, appended last. */
    RETURN_IF_ERROR(
        gitignore_ruleset_append_rules(
        rs, r->cli_rules, (gitignore_origin_t) IGNORE_ORIGIN_CLI
        )
    );

    *out = rs;
    return NULL;
}

error_t *ignore_blob_read(
    git_repository *repo, const char *refname, char **out_content, size_t *out_size
) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(out_content);
    CHECK_NULL(out_size);
    CHECK_ARG(refname[0] != '\0', "Reference name cannot be empty");

    *out_content = NULL;
    *out_size = 0;

    /* An absent ref is not an error — callers treat NULL content as "no
     * baseline/profile .dottaignore yet". */
    bool exists = false;
    RETURN_IF_ERROR(gitops_reference_exists(repo, refname, &exists));
    if (!exists) return NULL;

    /* Existence just verified, so a tree load failure is a real error (I/O,
     * corruption) rather than an absence; the loader names the ref. */
    git_tree *tree = NULL;
    RETURN_IF_ERROR(gitops_load_tree(repo, refname, &tree));

    const git_tree_entry *entry = git_tree_entry_byname(tree, ".dottaignore");
    if (!entry) {
        git_tree_free(tree);
        return NULL;
    }

    void *content = NULL;
    size_t size = 0;
    error_t *err = gitops_read_blob_content(
        repo, git_tree_entry_id(entry), &content, &size
    );
    git_tree_free(tree);
    if (err) return err;

    if (size > MAX_DOTTAIGNORE_SIZE) {
        free(content);
        return ERROR(
            ERR_VALIDATION,
            ".dottaignore at '%s' exceeds capacity (max %zu bytes, actual %zu)",
            refname, (size_t) MAX_DOTTAIGNORE_SIZE, size
        );
    }

    /* Treat empty blobs as absent — nothing to parse, and it lets callers use
     * "content == NULL" as the single "no source" check. */
    if (size == 0) {
        free(content);
        return NULL;
    }

    *out_content = content;
    *out_size = size;
    return NULL;
}

error_t *ignore_blob_text(
    git_repository *repo, const char *refname, char **out_text
) {
    size_t size = 0;
    RETURN_IF_ERROR(ignore_blob_read(repo, refname, out_text, &size));

    /* A NUL would end every string reading of the file — the rules compiled from
     * it, the lines --add and --remove rewrite — and what stood behind it would
     * be lost without a word. Here the bytes are still in hand with their
     * length. */
    if (*out_text && memchr(*out_text, '\0', size)) {
        free(*out_text);
        *out_text = NULL;
        return ERROR(
            ERR_VALIDATION,
            ".dottaignore at '%s' is not text: it holds a NUL byte", refname
        );
    }

    return NULL;
}

error_t *ignore_blob_write(
    git_repository *repo, const char *refname, const char *content,
    size_t size, const char *commit_msg
) {
    CHECK_NULL(repo);
    CHECK_NULL(refname);
    CHECK_NULL(content);
    CHECK_NULL(commit_msg);
    CHECK_ARG(refname[0] != '\0', "Reference name cannot be empty");

    if (size > MAX_DOTTAIGNORE_SIZE) {
        return ERROR(
            ERR_VALIDATION,
            ".dottaignore content exceeds capacity (max %zu bytes, actual %zu)",
            (size_t) MAX_DOTTAIGNORE_SIZE, size
        );
    }
    if (memchr(content, '\0', size)) {
        return ERROR(
            ERR_VALIDATION, ".dottaignore content is not text: it holds a NUL byte"
        );
    }

    stage_t *stage = NULL;
    RETURN_IF_ERROR(stage_open(repo, refname, &stage));

    error_t *err = stage_put(
        stage, ".dottaignore", content, size, GIT_FILEMODE_BLOB
    );
    if (!err) {
        err = stage_commit(stage, commit_msg, NULL);
    }
    stage_free(stage);
    return err;
}

error_t *ignore_excludes_compile(
    char *const *patterns, size_t count, arena_t *arena,
    const gitignore_ruleset_t **out
) {
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;
    if (count == 0) return NULL;

    gitignore_ruleset_t *rules = NULL;
    RETURN_IF_ERROR(gitignore_ruleset_create(arena, &rules));

    for (size_t i = 0; i < count; i++) {
        error_t *err = gitignore_ruleset_append_pattern(
            rules, patterns[i], (gitignore_origin_t) IGNORE_ORIGIN_CLI
        );
        if (err) {
            return error_wrap(err, "Invalid --exclude pattern");
        }
    }

    *out = rules;
    return NULL;
}

error_t *ignore_rules_create(
    git_repository *repo, const config_t *config,
    const gitignore_ruleset_t *cli_rules, arena_t *arena, ignore_rules_t **out
) {
    CHECK_NULL(repo);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;

    /* The baseline, compiled once for every profile the builder composes: the
     * blob, or the compiled defaults when the read answers none (ref missing,
     * file missing, or empty blob — all non-errors).
     *
     * Load errors are fatal: a corrupted or unreadable baseline, or one that is
     * not text, must surface, not silently drop safety defaults. The rules hold
     * their own copies of every string, so the Git buffer is freed as soon as
     * they are made. */
    gitignore_ruleset_t *baseline = NULL;
    RETURN_IF_ERROR(gitignore_ruleset_create(arena, &baseline));

    char *blob = NULL;
    error_t *err = ignore_blob_text(repo, BASELINE_REF, &blob);
    if (err) {
        return error_wrap(err, "Failed to load baseline .dottaignore");
    }

    ignore_origin_t origin = blob ? IGNORE_ORIGIN_BASELINE : IGNORE_ORIGIN_BUILTIN;
    err = gitignore_ruleset_append_file(
        baseline, blob ? blob : DEFAULT_DOTTAIGNORE, (gitignore_origin_t) origin
    );
    free(blob);
    if (err) {
        return error_wrap(err, "Failed to parse baseline .dottaignore");
    }

    /* The builder is published last, once every layer it holds is in hand. */
    ignore_rules_t *r = arena_calloc(arena, 1, sizeof(*r));
    if (!r) {
        return ERROR(ERR_MEMORY, "Failed to allocate ignore rules builder");
    }

    r->arena = arena;
    r->repo = repo;
    r->baseline_rules = baseline;
    r->baseline_origin = origin;
    r->config_rules = config ? config->ignore_ruleset : NULL;
    r->cli_rules = cli_rules;

    *out = r;
    return NULL;
}

error_t *ignore_rules_for_profile(
    ignore_rules_t *r, const char *profile, const gitignore_ruleset_t **out
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

    /* The ref's presence is the seed. It is made here and nowhere else, and once
     * it stands its tree is the user's — a pattern removed, the file emptied,
     * even the entry taken away by hand — so the question is the ref's, never
     * the file's. */
    bool seeded = false;
    RETURN_IF_ERROR(gitops_reference_exists(repo, BASELINE_REF, &seeded));
    if (seeded) {
        return NULL;
    }

    /* A root commit on an orphan's stage. A ref that appeared since the look —
     * two inits racing — is refused at the open or at the commit. */
    stage_t *stage = NULL;
    error_t *err = stage_orphan(repo, BASELINE_REF, &stage);
    if (!err) {
        err = stage_put(
            stage, ".dottaignore", DEFAULT_DOTTAIGNORE,
            strlen(DEFAULT_DOTTAIGNORE), GIT_FILEMODE_BLOB
        );
    }
    if (!err) {
        err = stage_commit(
            stage, "Initialize .dottaignore with default patterns", NULL
        );
    }
    stage_free(stage);
    return err;
}
