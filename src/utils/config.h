/**
 * config.h - Configuration file parsing
 *
 * Handles loading and parsing dotta configuration files. Config file format is
 * TOML-like with sections and key=value pairs.
 *
 * A setting whose value is one of a few words is read as the value the word names,
 * in the words of whoever owns them: base/output's for verbosity and color, and
 * this module's for the divergence strategies (config_strategies), which `sync
 * --diverged` also speaks — no module beneath the command owns them.
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
 * The file is read key by key, each in the type the schema gives it: a section
 * that is no table, a key the schema does not name, a value of another type or
 * outside its key's domain, and a string or a name holding a NUL are refused,
 * named by section and key — never read as the default, or cut short.
 *
 * The two pattern lists, [ignore] patterns and [encryption] auto_encrypt, are
 * compiled here, auto_encrypt whether or not encryption is enabled: a list that
 * is no array, and an entry that is no string, holds a NUL or makes no rule
 * (base/gitignore.h), refuse the load, the entry named by its line and column.
 */
error_t *config_load(config_t **out);

/**
 * The configuration with every key at its default
 *
 * Made in an arena of its own, which holds the struct, every value config_load
 * reads into it and both compiled rulesets; a default is a literal. NULL when
 * the arena or the struct cannot be allocated.
 */
config_t *config_create_default(void);

/**
 * Free the configuration: its arena, and with it everything it holds (NULL-safe)
 */
void config_free(config_t *config);

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

/**
 * The divergence strategies, by the word [sync] diverged_strategy and `sync
 * --diverged` take — the one spelling the config's read, the flag's parse
 * (config_parse_strategy), sync's receipts and hint, and completion share. Adding
 * a strategy is a row here and an enumerator of sync_strategy_t (include/config.h).
 */
typedef struct config_strategy {
    const char *name;
    sync_strategy_t strategy;
    const char *summary;          /* what it does, in a phrase */
} config_strategy_t;

#define CONFIG_STRATEGY_COUNT 5

extern const config_strategy_t config_strategies[CONFIG_STRATEGY_COUNT];

/**
 * The strategy a word names
 *
 * The vocabulary's one parse, for both of its sources: the config's [sync]
 * diverged_strategy, read at load, and `sync --diverged`. An unknown word is
 * refused (ERR_INVALID_ARG) with the words it could be; the caller names its
 * source around the refusal and repeats none of it.
 *
 * @param word The word (must not be NULL)
 * @param out  The strategy (must not be NULL)
 * @return Error or NULL on success
 */
error_t *config_parse_strategy(const char *word, sync_strategy_t *out);

#endif /* DOTTA_CONFIG_H */
