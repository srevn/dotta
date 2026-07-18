/**
 * export.h - Materialize profile content to the filesystem
 */

#ifndef DOTTA_CMD_EXPORT_H
#define DOTTA_CMD_EXPORT_H

#include <runtime.h>
#include <types.h>

/**
 * Export command options
 *
 * The trailing `positional_args` / `positional_count` pair is a raw
 * bucket populated by the spec engine; `export_post_parse` interprets
 * it into the user-facing `profile`/`file_path`/`commit` fields.
 * The profile is always explicit — export never discovers one via the
 * manifest, since its headline use case is disabled/foreign profiles.
 */
typedef struct {
    /* User-facing (read by cmd_export). */
    const char *profile;     /* Profile name (always required) */
    const char *file_path;   /* Path within profile (NULL = whole profile) */
    const char *commit;      /* Commit reference (NULL = HEAD) */
    const char *output;      /* Destination path ('-' = single-file stdout) */
    bool dry_run;            /* Validate everything, write nothing */
    bool verbose;            /* Per-entry progress lines */

    /* Raw positional bucket (engine-populated; interpreted in post_parse). */
    char **positional_args;
    size_t positional_count;
} cmd_export_options_t;

/**
 * Materialize profile content to the filesystem
 *
 * Export is a copy, not a deployment: nothing registers in state,
 * ownership is never applied, and dotta makes no ongoing claim over
 * the destination. Copies one profile branch's subtree verbatim —
 * layering is not composed and mounts are not mapped.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t *cmd_export(const dotta_ctx_t *ctx, const cmd_export_options_t *opts);

/**
 * Spec-engine command specification for `dotta export`.
 *
 * Registered in main.c. Defined in export.c beside the post_parse,
 * validate, and dispatch wrappers.
 */
extern const args_command_t spec_export;

#endif /* DOTTA_CMD_EXPORT_H */
