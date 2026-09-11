/**
 * config.c - Configuration file parsing implementation
 */

#include "utils/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomlc17.h>

#include "base/arena.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/output.h"
#include "sys/filesystem.h"

/* Default values */
#define DEFAULT_REPO_DIR "~/.local/share/dotta/repo"
#define DEFAULT_HOOKS_DIR "~/.config/dotta/hooks"
#define DEFAULT_CONFIG_DIR "~/.config/dotta"
#define DEFAULT_CONFIG_FILE "config.toml"

/*
 * The readers of one value, one per kind of key. Each reads the value in its
 * key's type, and within its domain where the key has one, or refuses it under
 * the key's name as the file spells it — "[section] key". A reader is asked only
 * about a key the file holds: one the file leaves out keeps its default.
 */

static error_t *read_bool(
    toml_datum_t value, const char *section, const char *key, bool *out
) {
    if (value.type != TOML_BOOLEAN) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: expected a boolean", section, key
        );
    }

    *out = value.u.boolean;
    return NULL;
}

/* An integer within [min, max]: the range is the key's domain, and the refusal
 * names it. */
static error_t *read_int(
    toml_datum_t value, const char *section, const char *key, int32_t min,
    int32_t max, int32_t *out
) {
    if (value.type != TOML_INT64) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: expected an integer", section, key
        );
    }
    if (value.u.int64 < min || value.u.int64 > max) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: %lld (must be between %d and %d)",
            section, key, (long long) value.u.int64, min, max
        );
    }

    *out = (int32_t) value.u.int64;
    return NULL;
}

/* The value as the C string it is read as. A TOML string keeps its length, and
 * a C string ends at its first NUL: one inside would cut the value short, in
 * silence, wherever it is read — so it is refused here, where the length is still
 * in hand. The string is the parse's, alive while the parse is. */
static error_t *read_text(
    toml_datum_t value, const char *section, const char *key, const char **out
) {
    if (value.type != TOML_STRING) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: expected a string", section, key
        );
    }
    if (memchr(value.u.str.ptr, '\0', (size_t) value.u.str.len)) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: the string holds a NUL byte",
            section, key
        );
    }

    *out = value.u.s;
    return NULL;
}

/* A string, copied into the configuration's arena over the default — a literal,
 * which nothing frees. */
static error_t *read_string(
    toml_datum_t value, const char *section, const char *key, arena_t *arena,
    const char **out
) {
    RETURN_IF_ERROR(read_text(value, section, key, out));

    /* The parse's string, then the arena's copy of it: the parse is gone once
     * the file is read, and the configuration is not. */
    *out = arena_strdup(arena, *out);
    return *out ? NULL : ERROR(ERR_MEMORY, "Failed to copy [%s] %s", section, key);
}

/* A path: a string, and not an empty one — leaving the key out is how the default
 * is asked for. */
static error_t *read_path(
    toml_datum_t value, const char *section, const char *key, arena_t *arena,
    const char **out
) {
    RETURN_IF_ERROR(read_string(value, section, key, arena, out));

    if (**out == '\0') {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: an empty path (leave the key out "
            "for the default)", section, key
        );
    }
    return NULL;
}

/* The three settings of a few words, each read as the value its word names by
 * the owner of the words (utils/config.h), whose refusal the key's name wraps. */
static error_t *read_verbosity(
    toml_datum_t value, const char *section, const char *key, output_verbosity_t *out
) {
    const char *word = NULL;
    RETURN_IF_ERROR(read_text(value, section, key, &word));

    error_t *err = output_parse_verbosity(word, out);
    return err ? error_wrap(err, "Invalid [%s] %s", section, key) : NULL;
}

static error_t *read_color(
    toml_datum_t value, const char *section, const char *key, output_color_mode_t *out
) {
    const char *word = NULL;
    RETURN_IF_ERROR(read_text(value, section, key, &word));

    error_t *err = output_parse_color_mode(word, out);
    return err ? error_wrap(err, "Invalid [%s] %s", section, key) : NULL;
}

static error_t *read_strategy(
    toml_datum_t value, const char *section, const char *key, sync_strategy_t *out
) {
    const char *word = NULL;
    RETURN_IF_ERROR(read_text(value, section, key, &word));

    error_t *err = config_parse_strategy(word, out);
    return err ? error_wrap(err, "Invalid [%s] %s", section, key) : NULL;
}

/**
 * A pattern list from its TOML value, compiled into `arena` in the order written:
 * each entry one rule of the grammar (base/gitignore.h), the line it would be
 * in a .dottaignore.
 *
 * Read while the parse is alive, because the value still has what a C string
 * loses: its length — a NUL inside an entry is refused, never a truncation —
 * and its position, which names the entry in the refusal. Compiled once, at load,
 * so a list is refused before any command acts, and whatever reads it borrows
 * the rules. The origin is not the config's to choose: core/ignore tags the
 * [ignore] layer where it composes it, and auto_encrypt reads no attribution.
 * Published only whole.
 */
static error_t *read_patterns(
    toml_datum_t value, const char *section, const char *key, arena_t *arena,
    const gitignore_ruleset_t **out
) {
    if (value.type != TOML_ARRAY) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid [%s] %s: expected an array of strings",
            section, key
        );
    }

    gitignore_ruleset_t *rules = NULL;
    RETURN_IF_ERROR(gitignore_ruleset_create(arena, &rules));

    for (int32_t i = 0; i < value.u.arr.size; i++) {
        toml_datum_t entry = value.u.arr.elem[i];
        if (entry.type != TOML_STRING) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid [%s] %s: the entry at line %d, column %d "
                "is not a string", section, key, entry.lineno, entry.colno
            );
        }
        if (memchr(entry.u.str.ptr, '\0', (size_t) entry.u.str.len)) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid [%s] %s: the entry at line %d, column %d "
                "holds a NUL byte", section, key, entry.lineno, entry.colno
            );
        }
        error_t *err = gitignore_ruleset_append_pattern(rules, entry.u.s, 0);
        if (err) {
            return error_wrap(
                err, "Invalid [%s] %s: the entry at line %d, column %d",
                section, key, entry.lineno, entry.colno
            );
        }
    }

    *out = rules;
    return NULL;
}

config_t *config_create_default(void) {
    /* The configuration is its arena's: the struct, every value read into it
     * and both compiled rulesets, gone at once with config_free. A default is a
     * literal, so nothing below can fail but the arena and the struct. */
    arena_t *arena = arena_create(0);
    if (!arena) {
        return NULL;
    }
    config_t *config = arena_calloc(arena, 1, sizeof(*config));
    if (!config) {
        arena_destroy(arena);
        return NULL;
    }
    config->arena = arena;

    /* Set defaults */
    config->repo_dir = DEFAULT_REPO_DIR;
    config->strict_mode = false;
    config->strict_ownership = false;
    config->auto_detect_new_files = true;  /* Default: detect new files */

    config->hooks_dir = DEFAULT_HOOKS_DIR;
    config->hook_timeout = 30;  /* Default: 30 seconds */
    config->pre_apply = true;
    config->post_apply = true;
    config->pre_add = false;
    config->post_add = false;
    config->pre_remove = false;
    config->post_remove = false;
    config->pre_update = false;
    config->post_update = false;
    config->pre_sync = false;
    config->post_sync = false;

    config->confirm_destructive = true;
    config->confirm_new_files = true;  /* Default: confirm before adding new files */

    /* [ignore] defaults */
    config->respect_gitignore = true;                 /* Default: respect .gitignore */

    config->verbosity = OUTPUT_NORMAL;
    config->color = OUTPUT_COLOR_AUTO;

    /* [commit] defaults - match current hardcoded behavior */
    config->commit_title = "{host}: {action} {profile}";
    config->commit_body =
        "Date: {datetime}\n"
        "User: {user}\n"
        "Host: {host}\n"
        "Profile: {profile}\n"
        "Files: {count}\n"
        "\n"
        "{action_past}:\n"
        "{files}";

    /* [sync] defaults */
    config->auto_pull = true;                   /* Default: auto-pull when remote ahead */
    config->diverged_strategy = DIVERGE_WARN;   /* Default: warn on divergence */

    /* [encryption] defaults. The Argon2id pair is not a config value: it is the
     * repository's epoch, minted by `dotta init --strength` (crypto/kdf.h). */
    config->encryption_enabled = false;            /* Default: disabled (opt-in) */
    config->session_timeout = 3600;                /* 1 hour */

    return config;
}

void config_free(config_t *config) {
    /* The struct is the arena's too: one destroy, and nothing freed by field. */
    if (config) {
        arena_destroy(config->arena);
    }
}

/**
 * The configuration file's path: $DOTTA_CONFIG_FILE when it is set, else the
 * default location.
 */
static error_t *config_get_path(char **out) {
    /* Check environment variable */
    const char *env_path = getenv("DOTTA_CONFIG_FILE");
    if (env_path && env_path[0] != '\0') {
        return fs_expand_tilde(env_path, out);
    }

    /* Use default location */
    char *config_dir = NULL;
    error_t *err = fs_expand_tilde(DEFAULT_CONFIG_DIR, &config_dir);
    if (err) {
        return err;
    }

    err = fs_path_join(config_dir, DEFAULT_CONFIG_FILE, out);
    free(config_dir);
    return err;
}

/**
 * One key of the schema, read from its value into its field — the one place a
 * key is named, typed and bounded. A key the schema does not name is refused,
 * never ignored.
 */
static error_t *read_key(
    toml_datum_t value,
    const char *section,
    const char *key,
    config_t *config
) {
    arena_t *arena = config->arena;

    if (strcmp(section, "core") == 0) {
        if (strcmp(key, "repo_dir") == 0)
            return read_path(value, section, key, arena, &config->repo_dir);
        if (strcmp(key, "strict_mode") == 0)
            return read_bool(value, section, key, &config->strict_mode);
        if (strcmp(key, "strict_ownership") == 0)
            return read_bool(value, section, key, &config->strict_ownership);
        if (strcmp(key, "auto_detect_new_files") == 0)
            return read_bool(value, section, key, &config->auto_detect_new_files);
    } else if (strcmp(section, "hooks") == 0) {
        if (strcmp(key, "hooks_dir") == 0)
            return read_path(value, section, key, arena, &config->hooks_dir);
        if (strcmp(key, "timeout") == 0)
            return read_int(value, section, key, 0, INT32_MAX, &config->hook_timeout);
        if (strcmp(key, "pre_apply") == 0)
            return read_bool(value, section, key, &config->pre_apply);
        if (strcmp(key, "post_apply") == 0)
            return read_bool(value, section, key, &config->post_apply);
        if (strcmp(key, "pre_add") == 0)
            return read_bool(value, section, key, &config->pre_add);
        if (strcmp(key, "post_add") == 0)
            return read_bool(value, section, key, &config->post_add);
        if (strcmp(key, "pre_remove") == 0)
            return read_bool(value, section, key, &config->pre_remove);
        if (strcmp(key, "post_remove") == 0)
            return read_bool(value, section, key, &config->post_remove);
        if (strcmp(key, "pre_update") == 0)
            return read_bool(value, section, key, &config->pre_update);
        if (strcmp(key, "post_update") == 0)
            return read_bool(value, section, key, &config->post_update);
        if (strcmp(key, "pre_sync") == 0)
            return read_bool(value, section, key, &config->pre_sync);
        if (strcmp(key, "post_sync") == 0)
            return read_bool(value, section, key, &config->post_sync);
    } else if (strcmp(section, "security") == 0) {
        if (strcmp(key, "confirm_destructive") == 0)
            return read_bool(value, section, key, &config->confirm_destructive);
        if (strcmp(key, "confirm_new_files") == 0)
            return read_bool(value, section, key, &config->confirm_new_files);
    } else if (strcmp(section, "ignore") == 0) {
        if (strcmp(key, "patterns") == 0)
            return read_patterns(value, section, key, arena, &config->ignore_ruleset);
        if (strcmp(key, "respect_gitignore") == 0)
            return read_bool(value, section, key, &config->respect_gitignore);
    } else if (strcmp(section, "output") == 0) {
        if (strcmp(key, "verbosity") == 0)
            return read_verbosity(value, section, key, &config->verbosity);
        if (strcmp(key, "color") == 0)
            return read_color(value, section, key, &config->color);
    } else if (strcmp(section, "commit") == 0) {
        if (strcmp(key, "title") == 0)
            return read_string(value, section, key, arena, &config->commit_title);
        if (strcmp(key, "body") == 0)
            return read_string(value, section, key, arena, &config->commit_body);
    } else if (strcmp(section, "sync") == 0) {
        if (strcmp(key, "auto_pull") == 0)
            return read_bool(value, section, key, &config->auto_pull);
        if (strcmp(key, "diverged_strategy") == 0)
            return read_strategy(value, section, key, &config->diverged_strategy);
    } else if (strcmp(section, "encryption") == 0) {
        if (strcmp(key, "enabled") == 0)
            return read_bool(value, section, key, &config->encryption_enabled);
        if (strcmp(key, "auto_encrypt") == 0)
            return read_patterns(value, section, key, arena, &config->auto_encrypt_ruleset);
        if (strcmp(key, "session_timeout") == 0)
            return read_int(value, section, key, -1, INT32_MAX, &config->session_timeout);
    }

    return ERROR(ERR_INVALID_ARG, "Unknown key '%s' in [%s]", key, section);
}

/**
 * Read the document into `config`, key by key in the order the file writes them.
 *
 * read_key is the schema: each section must be one of the sections below, and a
 * table; each key in it one read_key names, read in its type and within its domain.
 * A key the file leaves out keeps its default. The first key the schema refuses
 * fails the read, named by its section and key. The document is the parse's,
 * alive for this call and no longer (read_file).
 */
static error_t *read_sections(toml_datum_t top, config_t *config) {
    static const char *const sections[] = {
        "core",   "hooks",  "security", "ignore",
        "output", "commit", "sync",     "encryption", NULL
    };

    for (int32_t i = 0; i < top.u.tab.size; i++) {
        const char *section = top.u.tab.key[i];
        toml_datum_t table = top.u.tab.value[i];

        /* A quoted name may hold a NUL, and C reads only the name before it —
         * which may be one of the schema's. No name the schema knows holds one,
         * and the table's own length is the one place that says so. */
        if (strlen(section) != (size_t) top.u.tab.len[i]) {
            return ERROR(ERR_INVALID_ARG, "Unknown section: its name holds a NUL byte");
        }
        const char *const *known = sections;
        while (*known && strcmp(*known, section) != 0) {
            known++;
        }
        if (!*known) {
            return ERROR(ERR_INVALID_ARG, "Unknown section [%s]", section);
        }
        if (table.type != TOML_TABLE) {
            return ERROR(ERR_INVALID_ARG, "Invalid [%s]: expected a table", section);
        }

        for (int32_t k = 0; k < table.u.tab.size; k++) {
            const char *key = table.u.tab.key[k];
            if (strlen(key) != (size_t) table.u.tab.len[k]) {
                return ERROR(
                    ERR_INVALID_ARG, "Unknown key in [%s]: its name holds a NUL byte",
                    section
                );
            }
            RETURN_IF_ERROR(read_key(table.u.tab.value[k], section, key, config));
        }
    }
    return NULL;
}

/**
 * The configuration file at `path` into `config`. No file is an empty one: every
 * key keeps its default.
 *
 * Read through the funnel (sys/filesystem), so whether the file is there and
 * whether it can be read are one answer at the run's one reach: absence is the
 * read's own ERR_NOT_FOUND, and a file that is there but cannot be read, or is
 * no regular file, is refused rather than read as absent. The parse lives exactly
 * as long as the read of its sections, and every result is freed with toml_free,
 * as the library documents — a failed parse's too.
 */
static error_t *read_file(const char *path, config_t *config) {
    buffer_t text = BUFFER_INIT;
    error_t *err = fs_read_file(path, &text);
    if (err && err->code == ERR_NOT_FOUND) {
        /* No config file - every key keeps its default */
        error_free(err);
        return NULL;
    }
    RETURN_IF_ERROR(err);

    /* A read is capped at 256 MB, far below INT_MAX, and ends in the NUL the
     * parser checks for; the parse copies what it keeps. */
    toml_result_t result = toml_parse_named(text.data, (int) text.size, path);
    buffer_free(&text);

    err = result.ok
        ? read_sections(result.toptab, config)
        : ERROR(ERR_INVALID_ARG, "%s", result.errmsg);
    toml_free(result);
    return err;
}

error_t *config_load(config_t **out) {
    CHECK_NULL(out);

    *out = NULL;

    char *path = NULL;
    RETURN_IF_ERROR(config_get_path(&path));

    /* Start with defaults */
    config_t *config = config_create_default();
    if (!config) {
        free(path);
        return ERROR(ERR_MEMORY, "Failed to create config");
    }

    /* The file over the defaults: each key it names is checked as it is read
     * (read_key), so nothing is left to check after. */
    error_t *err = read_file(path, config);

    /* Every failure is wrapped once, with the file: the chain beneath it names
     * what in the file, and why. */
    if (err) {
        config_free(config);
        err = error_wrap(err, "Failed to load configuration '%s'", path);
    } else {
        *out = config;
    }
    free(path);
    return err;
}

const char *config_repo_dir_from_env(void) {
    const char *dir = getenv("DOTTA_REPO_DIR");
    return (dir && dir[0] != '\0') ? dir : NULL;
}

error_t *config_get_repo_dir(const config_t *config, char **out) {
    CHECK_NULL(out);

    /* Priority 1: Environment variable */
    const char *env_dir = config_repo_dir_from_env();
    if (env_dir) {
        return fs_expand_tilde(env_dir, out);
    }

    /* Priority 2: Config file */
    if (config) {
        return fs_expand_tilde(config->repo_dir, out);
    }

    /* Priority 3: Default */
    return fs_expand_tilde(DEFAULT_REPO_DIR, out);
}

const config_strategy_t config_strategies[CONFIG_STRATEGY_COUNT] = {
    { "warn",   DIVERGE_WARN,   "Report the divergence, resolve by hand" },
    { "rebase", DIVERGE_REBASE, "Rebase local commits onto the remote"   },
    { "merge",  DIVERGE_MERGE,  "Merge the remote into the local branch" },
    { "ours",   DIVERGE_OURS,   "Keep local, force-push over the remote" },
    { "theirs", DIVERGE_THEIRS, "Keep remote, reset the local branch"    },
};

error_t *config_parse_strategy(const char *word, sync_strategy_t *out) {
    CHECK_NULL(word);
    CHECK_NULL(out);

    for (size_t i = 0; i < CONFIG_STRATEGY_COUNT; i++) {
        if (strcmp(word, config_strategies[i].name) == 0) {
            *out = config_strategies[i].strategy;
            return NULL;
        }
    }
    return ERROR(
        ERR_INVALID_ARG,
        "Unknown divergence strategy '%s' (valid: warn, rebase, merge, ours, theirs)",
        word
    );
}
