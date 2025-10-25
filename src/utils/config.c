/**
 * config.c - Configuration file parsing implementation
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <tomlc17.h>

#include "base/error.h"
#include "base/filesystem.h"
#include "infra/path.h"

/* Default values */
#define DEFAULT_REPO_DIR "~/.local/share/dotta/repo"
#define DEFAULT_CONFIG_DIR "~/.config/dotta"
#define DEFAULT_CONFIG_FILE "config.toml"
#define DEFAULT_HOOKS_DIR "~/.config/dotta/hooks"
#define DEFAULT_IGNORE_FILE ".dottaignore"

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

    char **items = malloc((size_t)size * sizeof(char *));
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
    *out_count = (size_t)size;
    return true;
}

dotta_config_t *config_create_default(void) {
    dotta_config_t *config = calloc(1, sizeof(dotta_config_t));
    if (!config) {
        return NULL;
    }

    /* Set defaults */
    config->repo_dir = strdup(DEFAULT_REPO_DIR);
    config->strict_mode = false;
    config->auto_detect_new_files = true;  /* Default: detect new files */

    config->hooks_dir = strdup(DEFAULT_HOOKS_DIR);
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
    config->ignore_file = strdup(DEFAULT_IGNORE_FILE);  /* .dottaignore */
    config->respect_gitignore = true;  /* Default: respect .gitignore */

    config->verbosity = strdup("normal");
    config->color = strdup("auto");
    config->format = strdup("compact");

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
    config->auto_pull = true;  /* Default: auto-pull when remote ahead */
    config->diverged_strategy = strdup("warn");  /* Default: warn on divergence */

    /* [encryption] defaults */
    config->encryption_enabled = false;           /* Default: disabled (opt-in) */
    config->auto_encrypt_patterns = NULL;
    config->auto_encrypt_pattern_count = 0;
    config->encryption_opslimit = 10000;          /* Moderate security */
    config->session_timeout = 3600;               /* 1 hour */

    return config;
}

void config_free(dotta_config_t *config) {
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
    free(config->ignore_file);

    free(config->verbosity);
    free(config->color);
    free(config->format);

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

error_t *config_load(const char *config_path, dotta_config_t **out) {
    CHECK_NULL(out);

    error_t *err = NULL;
    char *path = NULL;

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
    toml_result_t result = toml_parse_file_ex(path);
    free(path);

    if (!result.ok) {
        return ERROR(ERR_INVALID_ARG, "Failed to parse config: %s", result.errmsg);
    }

    /* Start with defaults */
    dotta_config_t *config = config_create_default();
    if (!config) {
        toml_free(result);
        return ERROR(ERR_MEMORY, "Failed to create config");
    }

    /* Extract [core] section */
    toml_datum_t core = toml_get(result.toptab, "core");
    if (core.type == TOML_TABLE) {
        toml_datum_t repo_dir = toml_get(core, "repo_dir");
        if (repo_dir.type == TOML_STRING) {
            free(config->repo_dir);
            config->repo_dir = strdup(repo_dir.u.s);
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
        toml_datum_t hooks_dir = toml_get(hooks, "hooks_dir");
        if (hooks_dir.type == TOML_STRING) {
            free(config->hooks_dir);
            config->hooks_dir = strdup(hooks_dir.u.s);
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
        toml_datum_t file = toml_get(ignore, "file");
        if (file.type == TOML_STRING) {
            free(config->ignore_file);
            config->ignore_file = strdup(file.u.s);
        }

        toml_datum_t patterns = toml_get(ignore, "patterns");
        if (patterns.type == TOML_ARRAY) {
            /* Free existing patterns */
            if (config->ignore_patterns) {
                for (size_t i = 0; i < config->ignore_pattern_count; i++) {
                    free(config->ignore_patterns[i]);
                }
                free(config->ignore_patterns);
            }
            extract_string_array(patterns, &config->ignore_patterns, &config->ignore_pattern_count);
        }

        toml_datum_t respect_gitignore = toml_get(ignore, "respect_gitignore");
        if (respect_gitignore.type == TOML_BOOLEAN) {
            config->respect_gitignore = respect_gitignore.u.boolean;
        }
    }

    /* Extract [output] section */
    toml_datum_t output = toml_get(result.toptab, "output");
    if (output.type == TOML_TABLE) {
        toml_datum_t verbosity = toml_get(output, "verbosity");
        if (verbosity.type == TOML_STRING) {
            free(config->verbosity);
            config->verbosity = strdup(verbosity.u.s);
        }

        toml_datum_t color = toml_get(output, "color");
        if (color.type == TOML_STRING) {
            free(config->color);
            config->color = strdup(color.u.s);
        }

        toml_datum_t format = toml_get(output, "format");
        if (format.type == TOML_STRING) {
            free(config->format);
            config->format = strdup(format.u.s);
        }
    }

    /* Extract [commit] section */
    toml_datum_t commit = toml_get(result.toptab, "commit");
    if (commit.type == TOML_TABLE) {
        toml_datum_t title = toml_get(commit, "title");
        if (title.type == TOML_STRING) {
            free(config->commit_title);
            config->commit_title = strdup(title.u.s);
        }

        toml_datum_t body = toml_get(commit, "body");
        if (body.type == TOML_STRING) {
            free(config->commit_body);
            config->commit_body = strdup(body.u.s);
        }
    }

    /* Extract [sync] section */
    toml_datum_t sync = toml_get(result.toptab, "sync");
    if (sync.type == TOML_TABLE) {
        toml_datum_t auto_pull = toml_get(sync, "auto_pull");
        if (auto_pull.type == TOML_BOOLEAN) {
            config->auto_pull = auto_pull.u.boolean;
        }

        toml_datum_t diverged_strategy = toml_get(sync, "diverged_strategy");
        if (diverged_strategy.type == TOML_STRING) {
            free(config->diverged_strategy);
            config->diverged_strategy = strdup(diverged_strategy.u.s);
        }
    }

    /* Extract [encryption] section */
    toml_datum_t encryption = toml_get(result.toptab, "encryption");
    if (encryption.type == TOML_TABLE) {
        toml_datum_t enabled = toml_get(encryption, "enabled");
        if (enabled.type == TOML_BOOLEAN) {
            config->encryption_enabled = enabled.u.boolean;
        }

        /* Parse auto_encrypt patterns */
        toml_datum_t auto_encrypt = toml_get(encryption, "auto_encrypt");
        if (auto_encrypt.type == TOML_ARRAY) {
            /* Free existing patterns if any */
            if (config->auto_encrypt_patterns) {
                for (size_t i = 0; i < config->auto_encrypt_pattern_count; i++) {
                    free(config->auto_encrypt_patterns[i]);
                }
                free(config->auto_encrypt_patterns);
            }

            extract_string_array(auto_encrypt,
                                &config->auto_encrypt_patterns,
                                &config->auto_encrypt_pattern_count);
        }

        toml_datum_t opslimit = toml_get(encryption, "opslimit");
        if (opslimit.type == TOML_INT64) {
            config->encryption_opslimit = (uint64_t)opslimit.u.int64;
        }

        toml_datum_t session_timeout = toml_get(encryption, "session_timeout");
        if (session_timeout.type == TOML_INT64) {
            config->session_timeout = (int32_t)session_timeout.u.int64;
        }
    }

    /* Free TOML result */
    toml_free(result);

    /* Validate */
    err = config_validate(config);
    if (err) {
        config_free(config);
        return err;
    }

    *out = config;
    return NULL;
}

bool config_parse_bool(const char *value, bool default_value) {
    if (!value) {
        return default_value;
    }

    if (strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "1") == 0 ||
        strcasecmp(value, "on") == 0) {
        return true;
    }

    if (strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 ||
        strcasecmp(value, "0") == 0 ||
        strcasecmp(value, "off") == 0) {
        return false;
    }

    return default_value;
}

error_t *config_validate(const dotta_config_t *config) {
    CHECK_NULL(config);

    /* Validate verbosity */
    if (config->verbosity) {
        if (strcmp(config->verbosity, "quiet") != 0 &&
            strcmp(config->verbosity, "normal") != 0 &&
            strcmp(config->verbosity, "verbose") != 0 &&
            strcmp(config->verbosity, "debug") != 0) {
            return ERROR(ERR_INVALID_ARG,
                        "Invalid verbosity: %s (must be quiet/normal/verbose/debug)",
                        config->verbosity);
        }
    }

    /* Validate color */
    if (config->color) {
        if (strcmp(config->color, "auto") != 0 &&
            strcmp(config->color, "always") != 0 &&
            strcmp(config->color, "never") != 0) {
            return ERROR(ERR_INVALID_ARG,
                        "Invalid color: %s (must be auto/always/never)",
                        config->color);
        }
    }

    /* Validate format */
    if (config->format) {
        if (strcmp(config->format, "compact") != 0 &&
            strcmp(config->format, "detailed") != 0 &&
            strcmp(config->format, "json") != 0) {
            return ERROR(ERR_INVALID_ARG,
                        "Invalid format: %s (must be compact/detailed/json)",
                        config->format);
        }
    }

    /* Validate diverged_strategy */
    if (config->diverged_strategy) {
        if (strcmp(config->diverged_strategy, "warn") != 0 &&
            strcmp(config->diverged_strategy, "rebase") != 0 &&
            strcmp(config->diverged_strategy, "merge") != 0 &&
            strcmp(config->diverged_strategy, "ours") != 0 &&
            strcmp(config->diverged_strategy, "theirs") != 0) {
            return ERROR(ERR_INVALID_ARG,
                        "Invalid diverged_strategy: %s (must be warn/rebase/merge/ours/theirs)",
                        config->diverged_strategy);
        }
    }

    return NULL;
}

error_t *config_get_repo_dir(const dotta_config_t *config, char **out) {
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
