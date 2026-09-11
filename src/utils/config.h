/**
 * config.h - Configuration file parsing
 *
 * Handles loading and parsing dotta configuration files. Config file format is
 * TOML-like with sections and key=value pairs.
 */

#ifndef DOTTA_CONFIG_H
#define DOTTA_CONFIG_H

#include <types.h>
#include <config.h>

/**
 * Load configuration from file
 *
 * From $DOTTA_CONFIG_FILE, or ~/.config/dotta/config.toml when it is unset, read
 * through sys/filesystem at the run's reach.
 *
 * Returns default config if file doesn't exist (not an error). Anything else
 * the path is — a file that cannot be read, no regular file, a document that
 * does not parse or holds a key or a value the schema refuses — is an error,
 * wrapped once with the file's path.
 *
 * The two pattern lists, [ignore] patterns and [encryption] auto_encrypt, are
 * compiled here, auto_encrypt whether or not encryption is enabled: a list that
 * is no array, and an entry that is no string, holds a NUL or makes no rule
 * (base/gitignore.h), refuse the load, the entry named by its line and column.
 */
error_t *config_load(config_t **out);

/**
 * Create config with default values
 */
config_t *config_create_default(void);

/**
 * Free configuration
 */
void config_free(config_t *config);

/**
 * Validate configuration
 */
error_t *config_validate(const config_t *config);

/**
 * DOTTA_REPO_DIR as the environment sets it, or NULL
 *
 * The one reader of the variable: config_get_repo_dir's first priority, and
 * repo_open's note when the path it resolved holds no repository — the same reader,
 * so the note cannot name an origin the resolution did not use. Raw and borrowed
 * from the environment, unexpanded; an empty value is NULL.
 */
const char *config_repo_dir_from_env(void);

/**
 * Get repository directory from config or environment
 *
 * Priority:
 *   1. DOTTA_REPO_DIR environment variable (config_repo_dir_from_env)
 *   2. Config file repo_dir
 *   3. Default: ~/.local/share/dotta/repo
 */
error_t *config_get_repo_dir(const config_t *config, char **out);

#endif /* DOTTA_CONFIG_H */
