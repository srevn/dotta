/**
 * config.c - Configuration file parsing implementation
 */

#include "utils/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomlc17.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "crypto/kdf.h"
#include "infra/path.h"
#include "sys/filesystem.h"

/* Default values */
#define DEFAULT_REPO_DIR "~/.local/share/dotta/repo"
#define DEFAULT_CONFIG_DIR "~/.config/dotta"
#define DEFAULT_CONFIG_FILE "config.toml"
#define DEFAULT_HOOKS_DIR "~/.config/dotta/hooks"

/**
 * Argon2id strength presets.
 *
 * The user-friendly knob is `strength = "fast" | "balanced" | "paranoid"`;
 * `memory` (MiB) and `passes` exist as raw overrides for users who
 * want exact control. Wall-clock timings below are indicative only —
 * they were measured on a 2024-era laptop and scale with single-thread
 * memory bandwidth and L3 cache size.
 *
 * Adding a preset: append a row here. The lookup is linear; the
 * three-row count is the design ceiling, not a vector limit.
 */
typedef struct {
    const char *name;
    uint16_t memory_mib;
    uint8_t passes;
} encryption_strength_preset_t;

static const encryption_strength_preset_t ENCRYPTION_STRENGTH_PRESETS[] = {
    { "fast",     64,   3 },  /* ~250–400 ms; CI/test */
    { "balanced", 256,  3 },  /* ~1.0 s; recommended */
    { "paranoid", 1024, 4 },  /* ~4–6 s; slow but firm */
};
static const size_t ENCRYPTION_STRENGTH_PRESETS_COUNT =
    sizeof(ENCRYPTION_STRENGTH_PRESETS) / sizeof(ENCRYPTION_STRENGTH_PRESETS[0]);

/**
 * Default preset name used when [encryption] omits both `strength` and
 * the raw mib/passes overrides. Must match a row in the table above.
 */
#define DEFAULT_ENCRYPTION_STRENGTH "balanced"

/**
 * Helper: Extract string array from TOML array
 */
static bool extract_string_array(toml_datum_t arr, char ***out_items, size_t *out_count) {
    if (arr.type != TOML_ARRAY) {
        return false;
    }

    int32_t size = arr.u.arr.size;
    if (size == 0) {
        *out_items = NULL;
        *out_count = 0;
        return true;
    }

    char **items = malloc((size_t) size * sizeof(char *));
    if (!items) {
        return false;
    }

    for (int32_t i = 0; i < size; i++) {
        toml_datum_t elem = arr.u.arr.elem[i];
        if (elem.type != TOML_STRING) {
            /* Free allocated items on error */
            for (int32_t j = 0; j < i; j++) {
                free(items[j]);
            }
            free(items);
            return false;
        }
        items[i] = strdup(elem.u.s);
        if (!items[i]) {
            for (int32_t j = 0; j < i; j++) {
                free(items[j]);
            }
            free(items);
            return false;
        }
    }

    *out_items = items;
    *out_count = (size_t) size;
    return true;
}

/**
 * Helper: Safe string field assignment with allocation check
 *
 * Duplicates value first, then frees old content. This order is safe
 * even if *field and value alias (cannot happen here, but defensive).
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
 * Helper: Compile config->auto_encrypt_patterns into a gitignore ruleset.
 *
 * Populates config->auto_encrypt.{arena,rules}. Leaves both NULL when
 * encryption is disabled or no patterns are configured — consumers
 * treat NULL rules as the "no auto-encrypt applies" sentinel.
 *
 * Eager compile at load time: any per-pattern length or per-ruleset
 * rule-count violation surfaces once, at startup, via the existing
 * config_load error path — no per-command deferred failures.
 */
static error_t *config_compile_auto_encrypt(config_t *config) {
    if (!config->encryption_enabled || !config->auto_encrypt_patterns ||
        config->auto_encrypt_pattern_count == 0) {
        return NULL;
    }

    arena_t *arena = arena_create(0);
    if (!arena) {
        return ERROR(ERR_MEMORY, "Failed to allocate auto-encrypt arena");
    }

    gitignore_ruleset_t *rules = NULL;
    error_t *err = gitignore_ruleset_create(arena, &rules);
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Failed to allocate auto-encrypt ruleset");
    }

    /* Origin tag is unused — auto-encrypt has no per-rule attribution. */
    err = gitignore_ruleset_append_patterns(
        rules,
        (const char *const *) config->auto_encrypt_patterns,
        config->auto_encrypt_pattern_count,
        0
    );
    if (err) {
        arena_destroy(arena);
        return error_wrap(err, "Invalid auto-encrypt patterns");
    }

    config->auto_encrypt.arena = arena;
    config->auto_encrypt.rules = rules;
    return NULL;
}

/**
 * Helper: Validate that a TOML table contains only recognized keys
 *
 * Returns an error for the first unrecognized key found.
 * section_name is used in error messages — NULL means top-level
 * (where keys are section names).
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

    /* Set defaults */
    config->repo_dir = strdup(DEFAULT_REPO_DIR);
    config->strict_mode = false;
    config->auto_detect_new_files = true;  /* Default: detect new files */

    config->hooks_dir = strdup(DEFAULT_HOOKS_DIR);
    config->hook_timeout = 30;  /* Default: 30 seconds */
    config->pre_apply = true;
    config->post_apply = true;
    config->pre_add = false;
    config->post_add = false;
    config->pre_remove = false;
    config->post_remove = false;
    config->pre_update = false;
    config->post_update = false;

    config->confirm_destructive = true;
    config->confirm_new_files = true;  /* Default: confirm before adding new files */

    /* [ignore] defaults */
    config->ignore_patterns = NULL;
    config->ignore_pattern_count = 0;
    config->respect_gitignore = true;                  /* Default: respect .gitignore */

    config->verbosity = strdup("normal");
    config->color = strdup("auto");

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
    config->diverged_strategy = strdup("warn"); /* Default: warn on divergence */

    /* [encryption] defaults — match the "balanced" preset (~1.0 s
     * derivation on commodity HW). The parser overwrites these if the
     * user sets `strength`, `memory`, or `passes`. */
    config->encryption_enabled = false;            /* Default: disabled (opt-in) */
    config->auto_encrypt_patterns = NULL;
    config->auto_encrypt_pattern_count = 0;
    config->encryption_argon2_memory_mib = 256;    /* "balanced" preset */
    config->encryption_argon2_passes = 3;          /* "balanced" preset */
    config->session_timeout = 3600;                /* 1 hour */

    return config;
}

void config_free(config_t *config) {
    if (!config) {
        return;
    }

    free(config->repo_dir);

    free(config->hooks_dir);

    /* Free ignore patterns */
    if (config->ignore_patterns) {
        for (size_t i = 0; i < config->ignore_pattern_count; i++) {
            free(config->ignore_patterns[i]);
        }
        free(config->ignore_patterns);
    }

    free(config->verbosity);
    free(config->color);

    free(config->commit_title);
    free(config->commit_body);

    free(config->diverged_strategy);

    /* Free encryption patterns */
    if (config->auto_encrypt_patterns) {
        for (size_t i = 0; i < config->auto_encrypt_pattern_count; i++) {
            free(config->auto_encrypt_patterns[i]);
        }
        free(config->auto_encrypt_patterns);
    }

    /* Drop the compiled auto-encrypt ruleset. arena_destroy is NULL-safe
     * and owns the ruleset storage — no separate rules free needed. */
    arena_destroy(config->auto_encrypt.arena);

    free(config);
}

error_t *config_get_path(char **out) {
    CHECK_NULL(out);

    /* Check environment variable */
    const char *env_path = getenv("DOTTA_CONFIG_FILE");
    if (env_path && env_path[0] != '\0') {
        return path_expand_home(env_path, out);
    }

    /* Use default location */
    char *config_dir = NULL;
    error_t *err = path_expand_home(DEFAULT_CONFIG_DIR, &config_dir);
    if (err) {
        return err;
    }

    err = fs_path_join(config_dir, DEFAULT_CONFIG_FILE, out);
    free(config_dir);
    return err;
}

error_t *config_load(const char *config_path, config_t **out) {
    CHECK_NULL(out);

    error_t *err = NULL;
    char *path = NULL;
    config_t *config = NULL;
    toml_result_t result = { 0 };
    bool toml_needs_free = false;

    /* Determine config path */
    if (config_path) {
        path = strdup(config_path);
        if (!path) {
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }
    } else {
        err = config_get_path(&path);
        if (err) {
            return err;
        }
    }

    /* Check if file exists */
    if (!fs_file_exists(path)) {
        /* No config file - return defaults */
        free(path);
        *out = config_create_default();
        if (!*out) {
            return ERROR(ERR_MEMORY, "Failed to create default config");
        }
        return NULL;
    }

    /* Parse TOML file */
    result = toml_parse_file_ex(path);
    free(path);

    if (!result.ok) {
        return ERROR(ERR_INVALID_ARG, "Failed to parse config: %s", result.errmsg);
    }
    toml_needs_free = true;

    /* Start with defaults */
    config = config_create_default();
    if (!config) {
        err = ERROR(ERR_MEMORY, "Failed to create config");
        goto cleanup;
    }

    /* Validate top-level sections */
    static const char *known[] = {
        "core",   "hooks",  "security", "ignore",
        "output", "commit", "sync",     "encryption"
    };
    err = validate_known_keys(result.toptab, NULL, known, 8);
    if (err) goto cleanup;

    /* Extract [core] section */
    toml_datum_t core = toml_get(result.toptab, "core");
    if (core.type == TOML_TABLE) {
        static const char *known[] = { "repo_dir", "strict_mode", "auto_detect_new_files" };
        err = validate_known_keys(core, "core", known, 3);
        if (err) goto cleanup;

        toml_datum_t repo_dir = toml_get(core, "repo_dir");
        if (repo_dir.type == TOML_STRING) {
            err = set_string(&config->repo_dir, repo_dir.u.s);
            if (err) goto cleanup;
        }

        toml_datum_t strict_mode = toml_get(core, "strict_mode");
        if (strict_mode.type == TOML_BOOLEAN) {
            config->strict_mode = strict_mode.u.boolean;
        }

        toml_datum_t auto_detect_new_files = toml_get(core, "auto_detect_new_files");
        if (auto_detect_new_files.type == TOML_BOOLEAN) {
            config->auto_detect_new_files = auto_detect_new_files.u.boolean;
        }
    }

    /* Extract [hooks] section */
    toml_datum_t hooks = toml_get(result.toptab, "hooks");
    if (hooks.type == TOML_TABLE) {
        static const char *known[] = {
            "hooks_dir", "timeout",    "pre_apply",   "post_apply", "pre_add",
            "post_add",  "pre_remove", "post_remove", "pre_update", "post_update"
        };
        err = validate_known_keys(hooks, "hooks", known, 10);
        if (err) goto cleanup;

        toml_datum_t hooks_dir = toml_get(hooks, "hooks_dir");
        if (hooks_dir.type == TOML_STRING) {
            err = set_string(&config->hooks_dir, hooks_dir.u.s);
            if (err) goto cleanup;
        }

        toml_datum_t hook_timeout = toml_get(hooks, "timeout");
        if (hook_timeout.type == TOML_INT64) {
            if (hook_timeout.u.int64 < 0 || hook_timeout.u.int64 > INT32_MAX) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid timeout: %lld (must be between 0 and %d)",
                    (long long) hook_timeout.u.int64, INT32_MAX
                );
                goto cleanup;
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
    }

    /* Extract [security] section */
    toml_datum_t security = toml_get(result.toptab, "security");
    if (security.type == TOML_TABLE) {
        static const char *known[] = { "confirm_destructive", "confirm_new_files" };
        err = validate_known_keys(security, "security", known, 2);
        if (err) goto cleanup;

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
    toml_datum_t ignore = toml_get(result.toptab, "ignore");
    if (ignore.type == TOML_TABLE) {
        static const char *known[] = { "patterns", "respect_gitignore" };
        err = validate_known_keys(ignore, "ignore", known, 2);
        if (err) goto cleanup;

        toml_datum_t patterns = toml_get(ignore, "patterns");
        if (patterns.type == TOML_ARRAY) {
            /* Free existing default patterns, then reset to safe state
             * before extraction (prevents double-free on failure) */
            if (config->ignore_patterns) {
                for (size_t i = 0; i < config->ignore_pattern_count; i++) {
                    free(config->ignore_patterns[i]);
                }
                free(config->ignore_patterns);
                config->ignore_patterns = NULL;
                config->ignore_pattern_count = 0;
            }
            if (!extract_string_array(
                patterns, &config->ignore_patterns,
                &config->ignore_pattern_count
                )) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid ignore patterns: all elements must be strings"
                );
                goto cleanup;
            }
        }

        toml_datum_t respect_gitignore = toml_get(ignore, "respect_gitignore");
        if (respect_gitignore.type == TOML_BOOLEAN) {
            config->respect_gitignore = respect_gitignore.u.boolean;
        }
    }

    /* Extract [output] section */
    toml_datum_t output = toml_get(result.toptab, "output");
    if (output.type == TOML_TABLE) {
        static const char *known[] = { "verbosity", "color" };
        err = validate_known_keys(output, "output", known, 2);
        if (err) goto cleanup;

        toml_datum_t verbosity = toml_get(output, "verbosity");
        if (verbosity.type == TOML_STRING) {
            err = set_string(&config->verbosity, verbosity.u.s);
            if (err) goto cleanup;
        }

        toml_datum_t color = toml_get(output, "color");
        if (color.type == TOML_STRING) {
            err = set_string(&config->color, color.u.s);
            if (err) goto cleanup;
        }
    }

    /* Extract [commit] section */
    toml_datum_t commit = toml_get(result.toptab, "commit");
    if (commit.type == TOML_TABLE) {
        static const char *known[] = { "title", "body" };
        err = validate_known_keys(commit, "commit", known, 2);
        if (err) goto cleanup;

        toml_datum_t title = toml_get(commit, "title");
        if (title.type == TOML_STRING) {
            err = set_string(&config->commit_title, title.u.s);
            if (err) goto cleanup;
        }

        toml_datum_t body = toml_get(commit, "body");
        if (body.type == TOML_STRING) {
            err = set_string(&config->commit_body, body.u.s);
            if (err) goto cleanup;
        }
    }

    /* Extract [sync] section */
    toml_datum_t sync = toml_get(result.toptab, "sync");
    if (sync.type == TOML_TABLE) {
        static const char *known[] = { "auto_pull", "diverged_strategy" };
        err = validate_known_keys(sync, "sync", known, 2);
        if (err) goto cleanup;

        toml_datum_t auto_pull = toml_get(sync, "auto_pull");
        if (auto_pull.type == TOML_BOOLEAN) {
            config->auto_pull = auto_pull.u.boolean;
        }

        toml_datum_t diverged_strategy = toml_get(sync, "diverged_strategy");
        if (diverged_strategy.type == TOML_STRING) {
            err = set_string(&config->diverged_strategy, diverged_strategy.u.s);
            if (err) goto cleanup;
        }
    }

    /* Extract [encryption] section */
    toml_datum_t encryption = toml_get(result.toptab, "encryption");
    if (encryption.type == TOML_TABLE) {
        static const char *known[] = {
            "enabled", "auto_encrypt", "strength",
            "memory",  "passes",       "session_timeout"
        };
        err = validate_known_keys(encryption, "encryption", known, 6);
        if (err) goto cleanup;

        toml_datum_t enabled = toml_get(encryption, "enabled");
        if (enabled.type == TOML_BOOLEAN) {
            config->encryption_enabled = enabled.u.boolean;
        }

        /* Parse auto_encrypt patterns */
        toml_datum_t auto_encrypt = toml_get(encryption, "auto_encrypt");
        if (auto_encrypt.type == TOML_ARRAY) {
            /* Free existing patterns, then reset to safe state
             * before extraction (prevents double-free on failure) */
            if (config->auto_encrypt_patterns) {
                for (size_t i = 0; i < config->auto_encrypt_pattern_count; i++) {
                    free(config->auto_encrypt_patterns[i]);
                }
                free(config->auto_encrypt_patterns);
                config->auto_encrypt_patterns = NULL;
                config->auto_encrypt_pattern_count = 0;
            }
            if (!extract_string_array(
                auto_encrypt, &config->auto_encrypt_patterns,
                &config->auto_encrypt_pattern_count
                )) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid auto_encrypt patterns: all elements must be strings"
                );
                goto cleanup;
            }
        }

        /* Argon2id derivation parameters — sketch §9.3 resolution:
         *   - Both `memory` and `passes` set → use them.
         *     Warn-once if `strength` is also set (raw wins).
         *   - Exactly one of the raw pair set → ERR_INVALID_ARG.
         *   - Only `strength` set → look up preset.
         *   - Nothing set → defaults from config_create_default stand. */
        toml_datum_t strength = toml_get(encryption, "strength");
        toml_datum_t mib = toml_get(encryption, "memory");
        toml_datum_t passes = toml_get(encryption, "passes");

        const bool strength_set = (strength.type == TOML_STRING);
        const bool mib_set = (mib.type == TOML_INT64);
        const bool passes_set = (passes.type == TOML_INT64);

        if (mib_set != passes_set) {
            err = ERROR(
                ERR_INVALID_ARG,
                "[encryption] memory and passes must be set together "
                "(set both, or neither and use `strength` instead)"
            );
            goto cleanup;
        }

        if (mib_set) {
            /* Bounds-check using KDF_ARGON2_*_MIN/MAX (defense-in-depth
             * against the same constants kdf_validate_params re-checks at
             * the crypto boundary; see crypto/kdf.h's bounds rationale). */
            if (mib.u.int64 < KDF_ARGON2_MEMORY_MIB_MIN
                || mib.u.int64 > KDF_ARGON2_MEMORY_MIB_MAX) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid [encryption] memory: %lld MiB (must be %u..%u)",
                    (long long) mib.u.int64,
                    (unsigned) KDF_ARGON2_MEMORY_MIB_MIN,
                    (unsigned) KDF_ARGON2_MEMORY_MIB_MAX
                );
                goto cleanup;
            }
            if (passes.u.int64 < KDF_ARGON2_PASSES_MIN
                || passes.u.int64 > KDF_ARGON2_PASSES_MAX) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid [encryption] passes: %lld (must be %u..%u)",
                    (long long) passes.u.int64,
                    (unsigned) KDF_ARGON2_PASSES_MIN,
                    (unsigned) KDF_ARGON2_PASSES_MAX
                );
                goto cleanup;
            }
            config->encryption_argon2_memory_mib = (uint16_t) mib.u.int64;
            config->encryption_argon2_passes = (uint8_t) passes.u.int64;

            if (strength_set) {
                fprintf(
                    stderr,
                    "Warning: [encryption] strength = \"%s\" is ignored because "
                    "memory and passes are set explicitly.\n",
                    strength.u.s
                );
            }
        } else if (strength_set) {
            const encryption_strength_preset_t *preset = NULL;
            for (size_t i = 0; i < ENCRYPTION_STRENGTH_PRESETS_COUNT; i++) {
                if (strcmp(
                    strength.u.s,
                    ENCRYPTION_STRENGTH_PRESETS[i].name
                    ) == 0) {
                    preset = &ENCRYPTION_STRENGTH_PRESETS[i];
                    break;
                }
            }
            if (!preset) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid [encryption] strength: \"%s\" "
                    "(valid: \"fast\", \"balanced\", \"paranoid\")",
                    strength.u.s
                );
                goto cleanup;
            }
            config->encryption_argon2_memory_mib = preset->memory_mib;
            config->encryption_argon2_passes = preset->passes;
        }
        /* else: keep the balanced defaults set by config_create_default. */

        toml_datum_t session_timeout = toml_get(encryption, "session_timeout");
        if (session_timeout.type == TOML_INT64) {
            if (session_timeout.u.int64 < -1 || session_timeout.u.int64 > INT32_MAX) {
                err = ERROR(
                    ERR_INVALID_ARG,
                    "Invalid session_timeout: %lld (must be -1, 0, or positive seconds)",
                    (long long) session_timeout.u.int64
                );
                goto cleanup;
            }
            config->session_timeout = (int32_t) session_timeout.u.int64;
        }
    }

    /* Normal path: free TOML result, then validate config */
    toml_free(result);
    toml_needs_free = false;

    /* Validate */
    err = config_validate(config);
    if (err) {
        config_free(config);
        return err;
    }

    /* Materialize derived state (compiled auto-encrypt ruleset) after
     * validation. Pattern-compile errors are real config errors — same
     * failure class as invalid verbosity or out-of-range argon2 params. */
    err = config_compile_auto_encrypt(config);
    if (err) {
        config_free(config);
        return err;
    }

    *out = config;
    return NULL;

cleanup:
    if (toml_needs_free) {
        toml_free(result);
    }
    config_free(config);
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

    /* Validate verbosity */
    if (config->verbosity) {
        if (strcmp(config->verbosity, "quiet") != 0 &&
            strcmp(config->verbosity, "normal") != 0 &&
            strcmp(config->verbosity, "verbose") != 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "Invalid verbosity: %s (must be quiet/normal/verbose)",
                config->verbosity
            );
        }
    }

    /* Validate color */
    if (config->color) {
        if (strcmp(config->color, "auto") != 0 &&
            strcmp(config->color, "always") != 0 &&
            strcmp(config->color, "never") != 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "Invalid color: %s (must be auto/always/never)",
                config->color
            );
        }
    }

    /* Validate diverged_strategy */
    if (config->diverged_strategy) {
        if (strcmp(config->diverged_strategy, "warn") != 0 &&
            strcmp(config->diverged_strategy, "rebase") != 0 &&
            strcmp(config->diverged_strategy, "merge") != 0 &&
            strcmp(config->diverged_strategy, "ours") != 0 &&
            strcmp(config->diverged_strategy, "theirs") != 0) {
            return ERROR(
                ERR_INVALID_ARG,
                "Invalid diverged_strategy: %s "
                "(must be warn/rebase/merge/ours/theirs)",
                config->diverged_strategy
            );
        }
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

    /* Defense-in-depth Argon2 params bounds check. Same constants the
     * parse step already applied; this guards against a future code path
     * that mutates config_t after load (today there is none). The check
     * runs unconditionally — even with encryption disabled — because the
     * defaults set by config_create_default are within bounds and a
     * caller that flips `encryption_enabled = true` mid-session would
     * otherwise be deriving keys with whatever stale values the struct
     * carries. */
    error_t *kdf_err = kdf_validate_params(
        config->encryption_argon2_memory_mib,
        config->encryption_argon2_passes
    );
    if (kdf_err) {
        /* Re-wrap as INVALID_ARG so config-layer errors stay uniform —
         * kdf_validate_params returns ERR_CRYPTO for the parse-tampered
         * blob-header use case, which is wrong-class for a config error. */
        char *msg = strdup(error_message(kdf_err));
        error_free(kdf_err);
        error_t *wrapped = ERROR(
            ERR_INVALID_ARG, "Invalid [encryption] argon2 params: %s",
            msg ? msg : "(allocation failed)"
        );
        free(msg);
        return wrapped;
    }

    return NULL;
}

error_t *config_get_repo_dir(const config_t *config, char **out) {
    CHECK_NULL(out);

    /* Priority 1: Environment variable */
    const char *env_dir = getenv("DOTTA_REPO_DIR");
    if (env_dir && env_dir[0] != '\0') {
        return path_expand_home(env_dir, out);
    }

    /* Priority 2: Config file */
    if (config && config->repo_dir) {
        return path_expand_home(config->repo_dir, out);
    }

    /* Priority 3: Default */
    return path_expand_home(DEFAULT_REPO_DIR, out);
}
