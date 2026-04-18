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
 * Command options
 *
 * `profile` can be set either via `-p/--profile` or via a single
 * optional positional (mapped by `ignore_post_parse`).
 */
typedef struct {
    /* User-facing (read by cmd_ignore). */
    const char *profile;        /* Profile name (NULL for baseline or all profiles) */
    const char *test_path;      /* Path to test (NULL for edit mode) */
    bool verbose;               /* Print verbose output */
    char **add_patterns;        /* Patterns to add (NULL for none) */
    size_t add_count;           /* Number of patterns to add */
    char **remove_patterns;     /* Patterns to remove (NULL for none) */
    size_t remove_count;        /* Number of patterns to remove */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
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
error_t *cmd_ignore(const dotta_ctx_t *ctx, const cmd_ignore_options_t *opts);

/**
 * Spec-engine command specification for `dotta ignore`.
 *
 * Registered in cmds/registry.c. Defined in ignore.c beside the
 * dispatch wrapper.
 */
extern const args_command_t spec_ignore;

#endif /* DOTTA_CMD_IGNORE_H */
