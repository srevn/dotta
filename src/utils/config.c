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
#include "sys/filesystem.h"

/* Default values */
#define DEFAULT_REPO_DIR "~/.local/share/dotta/repo"
#define DEFAULT_CONFIG_DIR "~/.config/dotta"
#define DEFAULT_CONFIG_FILE "config.toml"

/**
 * Helper: Safe string field assignment with allocation check
 *
 * Duplicates value first, then frees old content. This order is safe even if
 * *field and value alias (cannot happen here, but defensive).
 */
static error_t *set_string(char **field, const char *value) {
    char *copy = strdup(value);
    if (!copy) {
        return ERROR(ERR_MEMORY, "Failed to allocate config string");
    }
    free(*field);
    *field = copy;
    return NULL;
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
    toml_datum_t value,
    const char *section,
    const char *key,
    arena_t *arena,
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

/**
 * Helper: Validate that a TOML table contains only recognized keys
 *
 * Returns an error for the first unrecognized key found. section_name is used
 * in error messages — NULL means top-level (where keys are section names).
 */
static error_t *validate_known_keys(
    toml_datum_t table,
    const char *section_name,
    const char **known,
    size_t known_count
) {
    if (table.type != TOML_TABLE) {
        return NULL;
    }
    for (int32_t i = 0; i < table.u.tab.size; i++) {
        bool recognized = false;
        for (size_t k = 0; k < known_count; k++) {
            if (strcmp(table.u.tab.key[i], known[k]) == 0) {
                recognized = true;
                break;
            }
        }
        if (!recognized) {
            if (section_name) {
                return ERROR(
                    ERR_INVALID_ARG, "Unknown key '%s' in [%s]",
                    table.u.tab.key[i], section_name
                );
            }
            return ERROR(
                ERR_INVALID_ARG, "Unknown section [%s]",
                table.u.tab.key[i]
            );
        }
    }
    return NULL;
}

config_t *config_create_default(void) {
    config_t *config = calloc(1, sizeof(config_t));
    if (!config) {
        return NULL;
    }

    /* The compiled pattern rulesets are the arena's, for the process. */
    config->arena = arena_create(0);

    /* Set defaults */
    config->repo_dir = strdup(DEFAULT_REPO_DIR);
    config->strict_mode = false;
    config->strict_ownership = false;
    config->auto_detect_new_files = true;  /* Default: detect new files */

    config->hooks_dir = strdup(DOTTA_DEFAULT_HOOKS_DIR);
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
    config->commit_title = strdup("{host}: {action} {profile}");
    config->commit_body = strdup(
        "Date: {datetime}\n"
        "User: {user}\n"
        "Host: {host}\n"
        "Profile: {profile}\n"
        "Files: {count}\n"
        "\n"
        "{action_past}:\n"
        "{files}"
    );

    /* [sync] defaults */
    config->auto_pull = true;                   /* Default: auto-pull when remote ahead */
    config->diverged_strategy = DIVERGE_WARN;   /* Default: warn on divergence */

    /* [encryption] defaults. The Argon2id pair is not a config value: it is the
     * repository's epoch, minted by `dotta init --strength` (crypto/kdf.h). */
    config->encryption_enabled = false;            /* Default: disabled (opt-in) */
    config->session_timeout = 3600;                /* 1 hour */

    /* One check for every allocation above: a default that failed to allocate
     * would reach config_validate as the wrong reason, or a reader as a NULL. */
    if (!config->arena || !config->repo_dir || !config->hooks_dir ||
        !config->commit_title || !config->commit_body) {
        config_free(config);
        return NULL;
    }

    return config;
}

void config_free(config_t *config) {
    if (!config) {
        return;
    }

    free(config->repo_dir);

    free(config->hooks_dir);

    free(config->commit_title);
    free(config->commit_body);

    /* Both compiled rulesets are the arena's; arena_destroy is NULL-safe. */
    arena_destroy(config->arena);

    free(config);
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
 * Read the document's sections into `config`, each key over its default.
 *
 * A key the document does not name keeps its default; a section or key the schema
 * does not know, and a value it refuses, fail the read. The document is the
 * parse's, alive for this call and no longer (read_file).
 */
static error_t *read_sections(toml_datum_t top, config_t *config) {
    /* Validate top-level sections */
    static const char *known[] = {
        "core",   "hooks",  "security", "ignore",
        "output", "commit", "sync",     "encryption"
    };
    RETURN_IF_ERROR(validate_known_keys(top, NULL, known, 8));

    /* Extract [core] section */
    toml_datum_t core = toml_get(top, "core");
    if (core.type == TOML_TABLE) {
        static const char *known[] = {
            "repo_dir", "strict_mode", "strict_ownership", "auto_detect_new_files"
        };
        RETURN_IF_ERROR(validate_known_keys(core, "core", known, 4));

        toml_datum_t repo_dir = toml_get(core, "repo_dir");
        if (repo_dir.type == TOML_STRING) {
            RETURN_IF_ERROR(set_string(&config->repo_dir, repo_dir.u.s));
        }

        toml_datum_t strict_mode = toml_get(core, "strict_mode");
        if (strict_mode.type == TOML_BOOLEAN) {
            config->strict_mode = strict_mode.u.boolean;
        }

        toml_datum_t strict_ownership = toml_get(core, "strict_ownership");
        if (strict_ownership.type == TOML_BOOLEAN) {
            config->strict_ownership = strict_ownership.u.boolean;
        }

        toml_datum_t auto_detect_new_files = toml_get(core, "auto_detect_new_files");
        if (auto_detect_new_files.type == TOML_BOOLEAN) {
            config->auto_detect_new_files = auto_detect_new_files.u.boolean;
        }
    }

    /* Extract [hooks] section */
    toml_datum_t hooks = toml_get(top, "hooks");
    if (hooks.type == TOML_TABLE) {
        static const char *known[] = {
            "hooks_dir",  "timeout",     "pre_apply",  "post_apply",
            "pre_add",    "post_add",    "pre_remove", "post_remove",
            "pre_update", "post_update", "pre_sync",   "post_sync"
        };
        RETURN_IF_ERROR(validate_known_keys(hooks, "hooks", known, 12));

        toml_datum_t hooks_dir = toml_get(hooks, "hooks_dir");
        if (hooks_dir.type == TOML_STRING) {
            RETURN_IF_ERROR(set_string(&config->hooks_dir, hooks_dir.u.s));
        }

        toml_datum_t hook_timeout = toml_get(hooks, "timeout");
        if (hook_timeout.type == TOML_INT64) {
            if (hook_timeout.u.int64 < 0 || hook_timeout.u.int64 > INT32_MAX) {
                return ERROR(
                    ERR_INVALID_ARG,
                    "Invalid timeout: %lld (must be between 0 and %d)",
                    (long long) hook_timeout.u.int64, INT32_MAX
                );
            }
            config->hook_timeout = (int32_t) hook_timeout.u.int64;
        }

        toml_datum_t pre_apply = toml_get(hooks, "pre_apply");
        if (pre_apply.type == TOML_BOOLEAN) {
            config->pre_apply = pre_apply.u.boolean;
        }

        toml_datum_t post_apply = toml_get(hooks, "post_apply");
        if (post_apply.type == TOML_BOOLEAN) {
            config->post_apply = post_apply.u.boolean;
        }

        toml_datum_t pre_add = toml_get(hooks, "pre_add");
        if (pre_add.type == TOML_BOOLEAN) {
            config->pre_add = pre_add.u.boolean;
        }

        toml_datum_t post_add = toml_get(hooks, "post_add");
        if (post_add.type == TOML_BOOLEAN) {
            config->post_add = post_add.u.boolean;
        }

        toml_datum_t pre_remove = toml_get(hooks, "pre_remove");
        if (pre_remove.type == TOML_BOOLEAN) {
            config->pre_remove = pre_remove.u.boolean;
        }

        toml_datum_t post_remove = toml_get(hooks, "post_remove");
        if (post_remove.type == TOML_BOOLEAN) {
            config->post_remove = post_remove.u.boolean;
        }

        toml_datum_t pre_update = toml_get(hooks, "pre_update");
        if (pre_update.type == TOML_BOOLEAN) {
            config->pre_update = pre_update.u.boolean;
        }

        toml_datum_t post_update = toml_get(hooks, "post_update");
        if (post_update.type == TOML_BOOLEAN) {
            config->post_update = post_update.u.boolean;
        }

        toml_datum_t pre_sync = toml_get(hooks, "pre_sync");
        if (pre_sync.type == TOML_BOOLEAN) {
            config->pre_sync = pre_sync.u.boolean;
        }

        toml_datum_t post_sync = toml_get(hooks, "post_sync");
        if (post_sync.type == TOML_BOOLEAN) {
            config->post_sync = post_sync.u.boolean;
        }
    }

    /* Extract [security] section */
    toml_datum_t security = toml_get(top, "security");
    if (security.type == TOML_TABLE) {
        static const char *known[] = { "confirm_destructive", "confirm_new_files" };
        RETURN_IF_ERROR(validate_known_keys(security, "security", known, 2));

        toml_datum_t confirm_destructive = toml_get(security, "confirm_destructive");
        if (confirm_destructive.type == TOML_BOOLEAN) {
            config->confirm_destructive = confirm_destructive.u.boolean;
        }

        toml_datum_t confirm_new_files = toml_get(security, "confirm_new_files");
        if (confirm_new_files.type == TOML_BOOLEAN) {
            config->confirm_new_files = confirm_new_files.u.boolean;
        }
    }

    /* Extract [ignore] section */
    toml_datum_t ignore = toml_get(top, "ignore");
    if (ignore.type == TOML_TABLE) {
        static const char *known[] = { "patterns", "respect_gitignore" };
        RETURN_IF_ERROR(validate_known_keys(ignore, "ignore", known, 2));

        toml_datum_t patterns = toml_get(ignore, "patterns");
        if (patterns.type != TOML_UNKNOWN) {
            RETURN_IF_ERROR(
                read_patterns(
                patterns, "ignore", "patterns", config->arena,
                &config->ignore_ruleset
                )
            );
        }

        toml_datum_t respect_gitignore = toml_get(ignore, "respect_gitignore");
        if (respect_gitignore.type == TOML_BOOLEAN) {
            config->respect_gitignore = respect_gitignore.u.boolean;
        }
    }

    /* Extract [output] section */
    toml_datum_t output = toml_get(top, "output");
    if (output.type == TOML_TABLE) {
        static const char *known[] = { "verbosity", "color" };
        RETURN_IF_ERROR(validate_known_keys(output, "output", known, 2));

        toml_datum_t verbosity = toml_get(output, "verbosity");
        if (verbosity.type == TOML_STRING) {
            error_t *err = output_parse_verbosity(verbosity.u.s, &config->verbosity);
            if (err) {
                return error_wrap(err, "Invalid [output] verbosity");
            }
        }

        toml_datum_t color = toml_get(output, "color");
        if (color.type == TOML_STRING) {
            error_t *err = output_parse_color_mode(color.u.s, &config->color);
            if (err) {
                return error_wrap(err, "Invalid [output] color");
            }
        }
    }

    /* Extract [commit] section */
    toml_datum_t commit = toml_get(top, "commit");
    if (commit.type == TOML_TABLE) {
        static const char *known[] = { "title", "body" };
        RETURN_IF_ERROR(validate_known_keys(commit, "commit", known, 2));

        toml_datum_t title = toml_get(commit, "title");
        if (title.type == TOML_STRING) {
            RETURN_IF_ERROR(set_string(&config->commit_title, title.u.s));
        }

        toml_datum_t body = toml_get(commit, "body");
        if (body.type == TOML_STRING) {
            RETURN_IF_ERROR(set_string(&config->commit_body, body.u.s));
        }
    }

    /* Extract [sync] section */
    toml_datum_t sync = toml_get(top, "sync");
    if (sync.type == TOML_TABLE) {
        static const char *known[] = { "auto_pull", "diverged_strategy" };
        RETURN_IF_ERROR(validate_known_keys(sync, "sync", known, 2));

        toml_datum_t auto_pull = toml_get(sync, "auto_pull");
        if (auto_pull.type == TOML_BOOLEAN) {
            config->auto_pull = auto_pull.u.boolean;
        }

        toml_datum_t diverged_strategy = toml_get(sync, "diverged_strategy");
        if (diverged_strategy.type == TOML_STRING) {
            error_t *err = config_parse_strategy(
                diverged_strategy.u.s, &config->diverged_strategy
            );
            if (err) {
                return error_wrap(err, "Invalid [sync] diverged_strategy");
            }
        }
    }

    /* Extract [encryption] section */
    toml_datum_t encryption = toml_get(top, "encryption");
    if (encryption.type == TOML_TABLE) {
        static const char *known[] = {
            "enabled", "auto_encrypt", "session_timeout"
        };
        RETURN_IF_ERROR(validate_known_keys(encryption, "encryption", known, 3));

        toml_datum_t enabled = toml_get(encryption, "enabled");
        if (enabled.type == TOML_BOOLEAN) {
            config->encryption_enabled = enabled.u.boolean;
        }

        toml_datum_t auto_encrypt = toml_get(encryption, "auto_encrypt");
        if (auto_encrypt.type != TOML_UNKNOWN) {
            RETURN_IF_ERROR(
                read_patterns(
                auto_encrypt, "encryption", "auto_encrypt", config->arena,
                &config->auto_encrypt_ruleset
                )
            );
        }

        toml_datum_t session_timeout = toml_get(encryption, "session_timeout");
        if (session_timeout.type == TOML_INT64) {
            if (session_timeout.u.int64 < -1 || session_timeout.u.int64 > INT32_MAX) {
                return ERROR(
                    ERR_INVALID_ARG,
                    "Invalid session_timeout: %lld (must be -1, 0, or positive seconds)",
                    (long long) session_timeout.u.int64
                );
            }
            config->session_timeout = (int32_t) session_timeout.u.int64;
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

    /* Read the file over the defaults, then validate the result. */
    error_t *err = read_file(path, config);
    if (!err) err = config_validate(config);

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

error_t *config_validate(const config_t *config) {
    CHECK_NULL(config);

    /* Validate repo_dir */
    if (!config->repo_dir || config->repo_dir[0] == '\0') {
        return ERROR(
            ERR_INVALID_ARG, "Invalid repo_dir: must be a non-empty path"
        );
    }

    /* Validate hook_timeout */
    if (config->hook_timeout < 0) {
        return ERROR(
            ERR_INVALID_ARG,
            "Invalid hook_timeout: %d "
            "(must be >= 0, where 0 means no timeout)",
            config->hook_timeout
        );
    }

    /* Validate hooks_dir */
    if (config->hooks_dir && config->hooks_dir[0] == '\0') {
        return ERROR(
            ERR_INVALID_ARG,
            "Invalid hooks_dir: empty string "
            "(must be a valid path or omitted for default)"
        );
    }

    /* Validate session_timeout */
    if (config->session_timeout < -1) {
        return ERROR(
            ERR_INVALID_ARG,
            "Invalid session_timeout: %d "
            "(must be -1, 0, or positive seconds)",
            config->session_timeout
        );
    }

    return NULL;
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
    if (config && config->repo_dir) {
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
