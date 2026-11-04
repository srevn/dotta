/**
 * diff.h - Show differences between profiles and filesystem
 *
 * The workspace mode previews the two verbs at the view's rows: each direction
 * lists the rows its verb acts on or refuses there — a file's content, kind or
 * claim, a directory's kind or claim — with a hunk where bytes differ. Under
 * --raw a run writes libgit2's patches alone, for a program, and says every line
 * of its own on stderr.
 *
 * Direction semantics (unified diff representation):
 * - DIFF_UPSTREAM:   old=filesystem, new=repo  — '-' lines are current on disk,
 *                    '+' lines are what apply would write. Use to preview apply.
 * - DIFF_DOWNSTREAM: old=repo, new=filesystem  — '-' lines are in repo,
 *                    '+' lines are local changes. Use to preview update.
 * - DIFF_BOTH:       Shows both directions with labelled sections.
 */

#ifndef DOTTA_CMD_DIFF_H
#define DOTTA_CMD_DIFF_H

#include <git2.h>
#include <runtime.h>
#include <types.h>

/**
 * Diff mode
 */
typedef enum {
    DIFF_WORKSPACE,           /* Workspace diff: profile ↔ filesystem (default) */
    DIFF_COMMIT_TO_COMMIT,    /* Compare two commits */
    DIFF_COMMIT_TO_WORKSPACE  /* Compare commit to workspace */
} diff_mode_t;

/**
 * Diff direction (for workspace mode only)
 *
 * Numeric 0 is reserved as the "unset" sentinel so post_parse can detect whether
 * the user supplied an explicit direction flag. The three real directions are
 * written by ARGS_FLAG_SET rows; post_parse maps unset→UPSTREAM after validating
 * mode compatibility.
 */
typedef enum {
    DIFF_DIR_UNSET = 0,  /* Internal sentinel (no flag seen yet). */
    DIFF_UPSTREAM,       /* old=filesystem, new=repo (apply preview). */
    DIFF_DOWNSTREAM,     /* old=repo, new=filesystem (update preview). */
    DIFF_BOTH            /* Show both directions in labelled sections. */
} diff_direction_t;

/**
 * What a run prints
 *
 * Each listed row's header with its patch or its sentence beneath, the names
 * alone, or libgit2's patch for a program. 0 is the patch, the spec engine's
 * "no flag given": --name-only and --raw are two ARGS_FLAG_SET rows on the field,
 * so giving both is the engine's refusal in its own words (base/args.c
 * apply_flag_set).
 */
typedef enum {
    DIFF_FORM_PATCH = 0,  /* Each listed row's header, its patch or its sentence beneath */
    DIFF_FORM_NAMES,      /* --name-only: the paths alone */
    DIFF_FORM_RAW         /* --raw: libgit2's patch, nothing of dotta's */
} diff_form_t;

/**
 * Command options
 *
 * `mode`, `commit1`, `commit2` are derived by `diff_post_parse` from the three
 * classified positional buckets (git refs, paths, profiles). `direction ==
 * DIFF_DIR_UNSET` (0) signals "no direction flag was supplied" so post_parse
 * can reject a direction in commit modes.
 */
typedef struct {
    /* User-facing (read by cmd_diff) */
    diff_mode_t mode;           /* Diff mode */
    char **paths;               /* Path filters, each a file or a directory */
    size_t path_count;          /* Number of paths */
    int direction;              /* Which direction to show */
    const char *commit1;        /* First commit (old) */
    const char *commit2;        /* Second commit (new, NULL = workspace) */
    char **profiles;            /* Profile names (NULL = use state/config) */
    size_t profile_count;       /* Number of profiles */
    int form;                   /* What to print (diff_form_t) */
    char **git_refs;            /* Classified git-ref positionals */
    size_t git_ref_count;
} cmd_diff_options_t;

/**
 * Show differences
 *
 * Compares files in profiles with their deployed versions.
 *
 * @param ctx Dispatch context (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
error_t cmd_diff(const dotta_ctx_t *ctx, const cmd_diff_options_t *opts);

/**
 * Spec-engine command specification for `dotta diff`.
 *
 * Registered in main.c's static `dotta_commands[]`; defined in diff.c beside
 * the classifier, post_parse, and dispatch wrappers.
 */
extern const args_command_t spec_diff;

#endif /* DOTTA_CMD_DIFF_H */
