/**
 * ignore.c - Layered `.dottaignore` ruleset builder and persistence.
 *
 * The builder holds the layers every profile shares — the baseline, compiled at
 * creation; the config's, compiled at load (utils/config) and borrowed; the CLI
 * layer, compiled once by ignore_excludes_compile and handed in — and lazily
 * composes a fresh per-profile ruleset on first call to `ignore_ruleset`.
 * Subsequent calls with the same profile name return the cached pointer —
 * memoisation lives in the builder, not in any caller bookkeeping.
 *
 * A compiled layer is composed by copying (gitignore_ruleset_append_rules): each
 * per-profile ruleset copies the baseline's, the config's and the CLI's rules
 * around the profile's own .dottaignore and borrows their strings, so what was
 * read once is not read again. The layers make one ruleset, not four verdicts:
 * a later layer's `!` has to be asked at the same rung as the earlier layer's
 * directory it re-opens (ignore.h).
 *
 * The source layer (sys/source.h) is not compiled with them: it reads the rules
 * of the repositories a path physically stands in, each rung of its own, so it
 * answers for the place, where the four answer for the name. The builder opens
 * it, and ignore_verdict asks both, the four first — the one place the ladder
 * is spelled.
 */

#include "core/ignore.h"

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/heap.h"
#include "infra/label.h"
#include "sys/gitops.h"
#include "sys/source.h"
#include "sys/stage.h"

/* Size cap on `.dottaignore` blobs — an ignore-specific policy guarding against
 * a runaway file pulled in from Git. The underlying gitignore engine already
 * caps per-pattern length and rule count. Typed as size_t so the multiplication
 * happens in size_t and the comparison against blob sizes stays warning-clean. */
#define MAX_DOTTAIGNORE_SIZE ((size_t) 1024 * 1024)   /* 1 MB */

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
    "# Patterns are matched against the path as seen from the directory it\n"
    "# deploys under, as a .gitignore at ~ (home/ files), at / (root/ files)\n"
    "# or at the deployment target (custom/ files) would match it:\n"
    "# `.config/Code/Cache/` is ~/.config/Code/Cache, never written with a\n"
    "# leading home/.\n"
    "#\n"
    "# This file uses .gitignore syntax:\n"
    "#   - Use # for comments\n"
    "#   - Use * ? [abc] for glob patterns\n"
    "#   - Use / at end to match only directories\n"
    "#   - Use ! to negate a pattern. A ! cannot re-open a directory an\n"
    "#     earlier pattern excluded: with `.cache/` above it, `!.cache/keep`\n"
    "#     does nothing and `!.cache/` is what re-opens it\n"
    "#   - Use / at start to anchor at the top of that directory (`/.cache/`\n"
    "#     is ~/.cache alone; `.cache/` is every .cache directory)\n"
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
    ".git\n"   /* no slash: a worktree's or a submodule's .git is a file */
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
    "# Patterns are matched against the path as seen from the directory it\n"
    "# deploys under, as a .gitignore at ~ (home/ files), at / (root/ files)\n"
    "# or at the deployment target (custom/ files) would match it:\n"
    "# `.config/Code/Cache/` is ~/.config/Code/Cache, never written with a\n"
    "# leading home/.\n"
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
    "#   - Use / at start to anchor at the top of that directory (`/.cache/`\n"
    "#     is ~/.cache alone; `.cache/` is every .cache directory)\n"
    "\n"
    "# Add your profile-specific patterns below:\n";

/* One entry in the per-profile memo (ignore_ruleset) */
typedef struct {
    const char *name;             /* the key; "" for baseline-only */
    gitignore_ruleset_t *ruleset;
} entry_t;

struct ignore_rules {
    arena_t *arena;                            /* borrowed; backs all of it */
    git_repository *repo;                      /* borrowed; profile blobs */

    /* The layers every profile shares (ignore_rules_create) */
    const gitignore_ruleset_t *baseline_rules; /* compiled at creation */
    ignore_origin_t baseline_origin;           /* BASELINE, or BUILTIN */
    const gitignore_ruleset_t *config_rules;   /* borrowed; compiled at load */
    const gitignore_ruleset_t *cli_rules;      /* borrowed; NULL when no -e */
    source_filter_t *source;                   /* the source layer; NULL: turned off */

    /* Memoised per-profile rulesets: a linear scan, as profiles are few */
    entry_t *profiles;
    size_t profile_count;
    size_t profile_capacity;
};

/**
 * Compose a fresh ruleset for `profile` in the builder's arena.
 *
 * Appends the four layers in precedence order (baseline/builtin, profile, config,
 * CLI) — the baseline's, the config's and the CLI's compiled rules copied, the
 * profile's .dottaignore read. A rung is read last rule first
 * (gitignore_ruleset_find), so CLI wins last-match and the ordering here
 * establishes the documented precedence for free.
 *
 * `profile` is the canonicalised key ("" means baseline-only).
 */
static error_t ignore_compose(
    ignore_rules_t *r, const char *profile, gitignore_ruleset_t **out
) {
    gitignore_ruleset_t *rs = gitignore_ruleset_create(r->arena, GITIGNORE_CASE_SENSITIVE);

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
        error_t err = ignore_blob_text(r->repo, refname, &content);
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

error_t ignore_blob_read(
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
    error_t err = gitops_read_blob_content(
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

error_t ignore_blob_text(
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

error_t ignore_blob_write(
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

    error_t err = stage_put(
        stage, ".dottaignore", content, size, GIT_FILEMODE_BLOB, NULL
    );
    if (!err) {
        err = stage_commit(stage, commit_msg, NULL);
    }
    stage_free(stage);
    return err;
}

error_t ignore_excludes_compile(
    char *const *patterns, size_t count, arena_t *arena,
    const gitignore_ruleset_t **out
) {
    CHECK_NULL(arena);
    CHECK_NULL(out);

    *out = NULL;
    if (count == 0) return NULL;

    gitignore_ruleset_t *rules = gitignore_ruleset_create(arena, GITIGNORE_CASE_SENSITIVE);

    for (size_t i = 0; i < count; i++) {
        error_t err = gitignore_ruleset_append_pattern(
            rules, patterns[i], (gitignore_origin_t) IGNORE_ORIGIN_CLI
        );
        if (err) {
            return error_wrap(err, "Invalid --exclude pattern");
        }
    }

    *out = rules;
    return NULL;
}

error_t ignore_rules_create(
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
    gitignore_ruleset_t *baseline = gitignore_ruleset_create(arena, GITIGNORE_CASE_SENSITIVE);

    char *blob = NULL;
    error_t err = ignore_blob_text(repo, BASELINE_REF, &blob);
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

    r->arena = arena;
    r->repo = repo;
    r->baseline_rules = baseline;
    r->baseline_origin = origin;
    r->config_rules = config ? config->ignore_ruleset : NULL;
    r->cli_rules = cli_rules;

    /* The source layer where the configuration respects it, in the builder's
     * arena: one filter for every question the command asks, so every directory
     * and rule file it reads is read once. */
    r->source = config && config->respect_gitignore ? source_filter_create(arena) : NULL;

    *out = r;
    return NULL;
}

error_t ignore_ruleset(
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

    /* Compose fresh and cache. */
    gitignore_ruleset_t *rs = NULL;
    RETURN_IF_ERROR(ignore_compose(r, key, &rs));

    r->profiles = arena_grow(
        r->arena, r->profiles, &r->profile_capacity, r->profile_count + 1,
        sizeof(*r->profiles)
    );

    r->profiles[r->profile_count].name = arena_strdup(r->arena, key);
    r->profiles[r->profile_count].ruleset = rs;
    r->profile_count++;

    *out = rs;
    return NULL;
}

source_filter_t *ignore_source(ignore_rules_t *r) {
    CHECK_NULL(r);

    return r->source;
}

/**
 * How many rungs a subject has: its components, a place's leading '/' being none
 * — a name's tail, or a place, never "/" — and "" none at all
 */
static size_t ignore_rungs(const char *subject) {
    if (!*subject) return 0;

    size_t rungs = 1;
    for (const char *c = subject + 1; *c; c++) rungs += *c == '/';

    return rungs;
}

/**
 * One rung deeper into a subject cut in place: the separator cut last put back,
 * and the next one cut — none past the last, where the whole subject is the rung
 * — so the subject reads as the rung asked. A first rung is never empty, so the
 * search starts a byte in: past a place's leading '/', or into a name's first
 * component.
 */
static char *ignore_descend(char *subject, char *cut) {
    if (cut) *cut = '/';
    cut = strchr(cut ? cut + 1 : subject + 1, '/');
    if (cut) *cut = '\0';

    return cut;
}

/**
 * Is the name's rung the place's own directory at the same height — one directory,
 * however each is spelled?
 *
 * At the path and at its directory always: the place is its directory's kernel
 * spelling and its own name. Above them, wherever no link the spelled place passes
 * through leads elsewhere: the directory the spelled rung is — the first `len`
 * bytes of `spelled` — as the kernel spells it, against the place's rung. A
 * spelling the filter cannot resolve is no directory it can call the place's.
 */
static bool ignore_shared(
    source_filter_t *source, const char *spelled, size_t len, const char *place, size_t rung
) {
    if (rung < 2) return true;

    /* The spelled rung through its '/', which stands behind it: a rung above
     * the path's directory is a directory the spelling goes on through. */
    const char *physical = NULL;
    if (source_filter_physical(source, spelled, len + 1, &physical)) return false;

    size_t n = strlen(place);
    return strncmp(physical, place, n) == 0 && physical[n] == '/' && physical[n + 1] == '\0';
}

error_t ignore_verdict(
    const gitignore_ruleset_t *rules, source_filter_t *source, const char *storage_path,
    const char *filesystem_path, path_kind_t kind, ignore_verdict_t *out
) {
    CHECK_NULL(storage_path);
    CHECK_NULL(out);

    *out = (ignore_verdict_t){ .origin = IGNORE_ORIGIN_NONE };

    /* The four, over the name's tail: one program, git's (base/gitignore.h
     * gitignore_eval) — the ancestors first, and the first rung a rule of theirs
     * excludes the verdict. They are the higher layers, so an exclusion of theirs
     * is final across the ladder too: the source layer is not asked. */
    const char *tail = label_tail(storage_path);
    const gitignore_match_t match = gitignore_eval(
        rules, tail, kind == PATH_KIND_DIRECTORY
    );
    if (match.rule) {
        *out = (ignore_verdict_t){
            (ignore_origin_t) gitignore_rule_origin(match.rule),
            gitignore_rule_pattern(match.rule), match.rung
        };
        return NULL;
    }

    /* Where they exclude nothing, the source layer, which reads where the place
     * physically stands: its directory as the kernel spells it, and its own name
     * as spelled — git follows no link, and reads one it meets at the end as an
     * entry. Without the layer, or a place, the four's answer stands, and a place
     * that names no entry ("/") asks nothing. */
    const char *spelled = source ? filesystem_path : NULL;
    const char *entry = spelled ? strrchr(spelled, '/') + 1 : NULL;
    if (!entry || !*entry) return NULL;

    /* The name's tail ends the spelled place component for component (cmds/add.h,
     * THE KEY INVARIANT): a contract, checked where the place is read, since
     * that is how a rung of the name is found in the place. */
    size_t tail_len = strlen(tail), len = strlen(spelled);
    CHECK_ARG(
        tail_len == 0 || (tail_len < len && spelled[len - tail_len - 1] == '/' &&
        memcmp(spelled + len - tail_len, tail, tail_len) == 0),
        "a name's tail ends the path it names"
    );
    size_t head = len - tail_len;

    /* A place whose directory resolves to nothing leaves the layer no rung, and
     * its failure is the answer, the four having excluded nothing. */
    const char *directory = NULL;
    error_t failure = source_filter_physical(
        source, spelled, (size_t) (entry - spelled), &directory
    );
    if (failure) return failure;

    /* The two subjects in one transient, the heap's, each cut in place at the
     * rung asked: the name's tail, and the place in the kernel's spelling. */
    size_t directory_len = strlen(directory), entry_len = strlen(entry);
    char *name = heap_alloc(tail_len + 1 + directory_len + entry_len + 1);
    memcpy(name, tail, tail_len + 1);

    char *place = name + tail_len + 1;
    memcpy(place, directory, directory_len);
    memcpy(place + directory_len, entry, entry_len + 1);

    /* Top down, git's order, each rung counted up from the path itself — 0 the
     * path, 1 its directory — in both subjects at once, as infra/pathspec counts
     * its two: the name runs out at its root, and the place climbs on to "/". */
    size_t name_rungs = ignore_rungs(name), place_rungs = ignore_rungs(place);
    char *name_cut = NULL, *place_cut = NULL;

    for (size_t rung = name_rungs > place_rungs ? name_rungs : place_rungs; rung-- > 0;) {
        bool is_dir = rung > 0 || kind == PATH_KIND_DIRECTORY;
        if (rung < name_rungs) name_cut = ignore_descend(name, name_cut);
        if (rung >= place_rungs) continue;
        place_cut = ignore_descend(place, place_cut);

        /* The place's rung, asked of its own directory's repository — a nested
         * repository's root of the one around it, as a walk meets it, and home's
         * own entries of home, as git asked from there judges them. */
        source_rule_t found;
        error_t err = source_filter_find(source, place, is_dir, &found);
        if (!err && (!found.rule || gitignore_rule_negated(found.rule))) continue;

        /* A `!` of the four re-opens its rung against the source's rules too,
         * where the name's rung is the place's own directory — asked where the
         * source excludes the rung or cannot read it, the four having excluded
         * nothing, so a rule of theirs at a rung is a `!` or none. A rung of
         * the place no rung of the name is — above the name's top, or above a
         * link the spelled place passes through — is the source layer's alone. */
        if (rung < name_rungs &&
            gitignore_rule_negated(gitignore_ruleset_find(rules, name, is_dir)) &&
            ignore_shared(source, spelled, head + strlen(name), place, rung)) {
            continue;
        }

        /* A rung it cannot read is no verdict, since a rung beneath it that a
         * rule excludes excludes the path whatever this one says: the first failure
         * is kept, and the climb goes on. */
        if (err) {
            if (!failure) failure = err;
            continue;
        }
        *out = (ignore_verdict_t){
            IGNORE_ORIGIN_SOURCE, gitignore_rule_pattern(found.rule), rung
        };
        break;
    }
    free(name);

    /* A failure is the answer only where nothing excluded the path. */
    return out->origin == IGNORE_ORIGIN_NONE ? failure : NULL;
}

const char *ignore_origin_describe(ignore_origin_t origin) {
    switch (origin) {
        case IGNORE_ORIGIN_NONE:     return "not ignored";
        case IGNORE_ORIGIN_SOURCE:   return "source .gitignore";
        case IGNORE_ORIGIN_BUILTIN:  return "built-in defaults";
        case IGNORE_ORIGIN_BASELINE: return "baseline .dottaignore";
        case IGNORE_ORIGIN_PROFILE:  return "profile .dottaignore";
        case IGNORE_ORIGIN_CONFIG:   return "config file patterns";
        case IGNORE_ORIGIN_CLI:      return "CLI --exclude patterns";
    }
    CHECK_ARG(false, "an ignore origin no enumerator names");
}

const char *ignore_baseline_defaults(void) {
    return DEFAULT_DOTTAIGNORE;
}

const char *ignore_profile_template(void) {
    return PROFILE_DOTTAIGNORE;
}

error_t ignore_seed_baseline(git_repository *repo) {
    CHECK_NULL(repo);

    /* The ref's presence is the seed. It is made here and nowhere else, and once
     * it stands its tree is the user's — a pattern removed, the file emptied,
     * even the entry taken away by hand — so the question is the ref's, never
     * the file's. */
    bool seeded = false;
    RETURN_IF_ERROR(gitops_reference_exists(repo, BASELINE_REF, &seeded));
    if (seeded) return NULL;

    /* A root commit on an orphan's stage. A ref that appeared since the look —
     * two inits racing — is refused at the open or at the commit. */
    stage_t *stage = NULL;
    error_t err = stage_orphan(repo, BASELINE_REF, &stage);
    if (!err) {
        err = stage_put(
            stage, ".dottaignore", DEFAULT_DOTTAIGNORE,
            strlen(DEFAULT_DOTTAIGNORE), GIT_FILEMODE_BLOB, NULL
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
