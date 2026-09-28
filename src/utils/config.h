/**
 * config.h - Configuration file parsing
 *
 * Handles loading and parsing dotta configuration files. Config file format is
 * TOML, with sections and key = value pairs.
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
 *
 * The two directories are settled here too, each read as the shell reads a path
 * (sys/filesystem.h fs_make_absolute: the tilde expanded, a relative one joined
 * onto the working directory, the whole folded), so every reader meets one
 * spelling: [hooks] hooks_dir, and the store's — DOTTA_REPO_DIR where it is set,
 * else [core] repo_dir, else the default beneath HOME. A `~user` spelling is
 * refused here, named by its key or by the variable, whether or not the command
 * would have read it.
 *
 * @param arena The arena the configuration lives in — the process's, main's
 *              (include/runtime.h); a refused load leaves its parts there (must
 *              not be NULL)
 * @param out   The configuration (must not be NULL)
 * @return Error or NULL on success
 */
error_t config_load(arena_t *arena, config_t **out);

/**
 * The configuration with every key at its default
 *
 * Made in `arena`, which then holds the struct, every value config_load reads
 * into it and both compiled rulesets; a default is a literal, or a directory
 * spelled beneath the invoker's HOME — so the identity is established first
 * (sys/identity.h identity_init), as main() orders it. Nothing frees a
 * configuration: it goes with its arena.
 *
 * @param arena The arena it lives in (must not be NULL)
 * @return The configuration; never NULL
 */
config_t *config_create_default(arena_t *arena);

/**
 * DOTTA_REPO_DIR as the environment sets it, or NULL
 *
 * The one reader of the variable: config_load's override of the store's directory,
 * and repo_open's note when that directory holds no repository — the same reader,
 * so the note cannot name an origin the load did not use. Raw and borrowed from
 * the environment, unexpanded; an empty value is NULL.
 */
const char *config_repo_dir_from_env(void);

/**
 * The divergence strategies, by the word [sync] diverged_strategy and `sync
 * --diverged` take — the one spelling the config's read, the flag's parse
 * (config_parse_strategy), sync's receipts and hint, and completion share. Indexed
 * by the strategy each names, so a strategy's word is a lookup, never a search:
 * adding one is an enumerator of sync_strategy_t (include/config.h), a row here
 * and an arm in cmds/sync. `sync --help` restates the phrases, and a test holds
 * it to them.
 */
typedef struct config_strategy {
    const char *name;
    const char *summary;          /* what it does, in a phrase */
} config_strategy_t;

#define CONFIG_STRATEGY_COUNT (SYNC_STRATEGY_THEIRS + 1)

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
error_t config_parse_strategy(const char *word, sync_strategy_t *out);

#endif /* DOTTA_CONFIG_H */
