/**
 * config.h - Configuration file parsing
 *
 * Handles loading and parsing dotta configuration files.
 * Config file format is TOML-like with sections and key=value pairs.
 */

#ifndef DOTTA_CONFIG_H
#define DOTTA_CONFIG_H

#include <types.h>
#include <config.h>

/**
 * Load configuration from file
 *
 * If config_path is NULL, uses default location:
 *   $DOTTA_CONFIG_FILE or ~/.config/dotta/config.toml
 *
 * Returns default config if file doesn't exist (not an error).
 */
error_t *config_load(const char *config_path, config_t **out);

/**
 * Create config with default values
 */
config_t *config_create_default(void);

/**
 * Free configuration
 */
void config_free(config_t *config);

/**
 * Get config file path (checks env vars and defaults)
 */
error_t *config_get_path(char **out);

/**
 * Validate configuration
 */
error_t *config_validate(const config_t *config);

/**
 * Get repository directory from config or environment
 *
 * Priority:
 *   1. DOTTA_REPO_DIR environment variable
 *   2. Config file repo_dir
 *   3. Default: ~/.local/share/dotta/repo
 */
error_t *config_get_repo_dir(const config_t *config, char **out);

#endif /* DOTTA_CONFIG_H */
