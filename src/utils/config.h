/**
 * config.h - Configuration file parsing
 *
 * Handles loading and parsing dotta configuration files.
 * Config file format is TOML-like with sections and key=value pairs.
 */

#ifndef DOTTA_CONFIG_H
#define DOTTA_CONFIG_H

#include <stdbool.h>

#include "base/error.h"
#include "types.h"

/**
 * Sync mode - determines which branches to fetch/sync
 */
typedef enum {
    SYNC_MODE_LOCAL,  /* Sync all local branches + discover new remote branches (default) */
    SYNC_MODE_AUTO,   /* Sync only auto-detected profiles (global, os, hosts/<hostname>) */
    SYNC_MODE_ALL     /* Fetch and sync all remote branches (like clone) */
} sync_mode_t;

/**
 * Configuration structure
 */
typedef struct {
    /* [core] */
    char *repo_dir;
    bool auto_detect;
    bool strict_mode;
    bool auto_detect_new_files;  /* Auto-detect new files in tracked directories */

    /* [profiles] */
    char **profile_order;
    size_t profile_order_count;

    /* [hooks] */
    char *hooks_dir;
    bool pre_apply;
    bool post_apply;
    bool pre_add;
    bool post_add;
    bool pre_remove;
    bool post_remove;
    bool pre_clean;
    bool post_clean;

    /* [security] */
    bool confirm_destructive;
    bool confirm_new_files;  /* Require confirmation before adding new files */

    /* [ignore] */
    char **ignore_patterns;       /* Array of patterns from config */
    size_t ignore_pattern_count;
    char *ignore_file;            /* Path to .dottaignore (default: $REPO/.dottaignore) */
    bool respect_gitignore;       /* Check .gitignore in source directories */

    /* [output] */
    char *verbosity;      /* "quiet", "normal", "verbose", "debug" */
    char *color;          /* "auto", "always", "never" */
    char *format;         /* "compact", "detailed", "json" */

    /* [commit] */
    char *commit_title;   /* Title template for commits */
    char *commit_body;    /* Body template for commits */

    /* [sync] */
    sync_mode_t sync_mode;       /* Sync mode: local, auto, or all */
    bool auto_pull;              /* Auto-pull when remote is ahead (default: true) */
    char *diverged_strategy;     /* Strategy for diverged branches: warn, rebase, merge, ours, theirs */
} dotta_config_t;

/**
 * Load configuration from file
 *
 * If config_path is NULL, uses default location:
 *   $DOTTA_CONFIG_FILE or ~/.config/dotta/config.toml
 *
 * Returns default config if file doesn't exist (not an error).
 */
error_t *config_load(const char *config_path, dotta_config_t **out);

/**
 * Create config with default values
 */
dotta_config_t *config_create_default(void);

/**
 * Free configuration
 */
void config_free(dotta_config_t *config);

/**
 * Get config file path (checks env vars and defaults)
 */
error_t *config_get_path(char **out);

/**
 * Get boolean value from config string
 */
bool config_parse_bool(const char *value, bool default_value);

/**
 * Validate configuration
 */
error_t *config_validate(const dotta_config_t *config);

/**
 * Get repository directory from config or environment
 *
 * Priority:
 *   1. DOTTA_REPO_DIR environment variable
 *   2. Config file repo_dir
 *   3. Default: ~/.local/share/dotta/repo
 */
error_t *config_get_repo_dir(const dotta_config_t *config, char **out);

#endif /* DOTTA_CONFIG_H */
