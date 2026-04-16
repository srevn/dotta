/**
 * registry.h - Root command registry for dotta
 *
 * The single place that names every top-level command the CLI exposes.
 * Consumers project this array into behavior:
 *
 *   - the main dispatcher in src/main.c resolves argv[1] against the
 *     registry and hands the matched spec to the spec engine;
 *   - the fish completion exporter in src/cmds/completion.c walks the
 *     registry and emits `complete -c dotta ...` lines for each entry.
 *
 * The array is NULL-terminated so iteration is a plain
 * `for (size_t i = 0; dotta_root_commands[i] != NULL; i++)` loop.
 */

#ifndef DOTTA_CMD_REGISTRY_H
#define DOTTA_CMD_REGISTRY_H

#include "base/args.h"

/**
 * NULL-terminated array of every user-facing top-level command.
 *
 * Ordering follows the narrative grouping used by `dotta --help`:
 * setup/inspection first, then sync, then admin/meta commands. Keep
 * new commands in the group that best fits their user flow.
 */
extern const args_command_t *const dotta_root_commands[];

#endif /* DOTTA_CMD_REGISTRY_H */
