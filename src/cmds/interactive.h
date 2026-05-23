/**
 * interactive.h - Interactive TUI for profile management and ordering
 *
 * The implementation is fully file-local to interactive.c. This header
 * exposes only the spec-engine command record. The TUI is reached via
 * `dotta interactive`, `dotta --interactive`, or `dotta -i`; the latter
 * two flag forms are resolved by args_resolve_root() in main.c through
 * the spec's `root_aliases` field.
 */

#ifndef DOTTA_CMD_INTERACTIVE_H
#define DOTTA_CMD_INTERACTIVE_H

#include "base/args.h"

extern const args_command_t spec_interactive;

#endif /* DOTTA_CMD_INTERACTIVE_H */
