/**
 * ignore.h - Manage ignore patterns
 *
 * Edit, view, and test ignore patterns across all layers.
 */

#ifndef DOTTA_CMD_IGNORE_H
#define DOTTA_CMD_IGNORE_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * What a run of `dotta ignore` does, one per run (ignore_post_parse)
 */
typedef enum {
    IGNORE_MODE_EDIT,           /* No mode's flag: the .dottaignore, in the editor */
    IGNORE_MODE_MODIFY,         /* --add, --remove: the .dottaignore, rule by rule */
    IGNORE_MODE_TEST,           /* --test: the ladder's verdict on a path, per asker */
    IGNORE_MODE_DEFAULTS        /* --list-defaults: the compiled defaults */
} ignore_mode_t;

/**
 * Command options
 *
 * `profile` is written by `-p/--profile` or by the one optional positional —
 * the same field: once the flag has written it, a positional is unexpected. `mode`
 * is settled by the parse, from the flags that make one (ignore_post_parse).
 */
typedef struct {
    /* User-facing (read by cmd_ignore). */
    ignore_mode_t mode;         /* What the run does, settled by ignore_post_parse */
    const char *profile;        /* Profile name (NULL for baseline or all profiles) */
    const char *test_path;      /* Path to test (IGNORE_MODE_TEST) */
    int verbosity;              /* dotta_verbosity_t (int for ARGS_FLAG_SET) */
    char **add_patterns;        /* Patterns to add (NULL for none) */
    size_t add_count;           /* Number of patterns to add */
    char **remove_patterns;     /* Patterns to remove (NULL for none) */
    size_t remove_count;        /* Number of patterns to remove */

    /* Read by ignore_post_parse alone. */
    bool list_defaults;         /* --list-defaults: IGNORE_MODE_DEFAULTS */
} cmd_ignore_options_t;

/**
 * Manage ignore patterns
 *
 * Allows editing, viewing, and testing ignore patterns.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_ignore(const dotta_ctx_t *ctx, const cmd_ignore_options_t *opts);

/**
 * Spec-engine command specification for `dotta ignore`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in ignore.c beside
 * the dispatch wrapper.
 */
extern const args_command_t spec_ignore;

#endif /* DOTTA_CMD_IGNORE_H */
