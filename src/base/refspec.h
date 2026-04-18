/**
 * refspec.h - Refspec parsing utilities
 *
 * Provides parsing for the refspec syntax: [profile:]<path>[@commit]
 * Used by commands that need to reference files with optional profile/commit context.
 */

#ifndef DOTTA_REFSPEC_H
#define DOTTA_REFSPEC_H

#include <types.h>

/**
 * Parsed refspec components.
 *
 * String fields point into the arena supplied to parse_refspec, which
 * owns their storage — the caller MUST NOT free them individually. A
 * field is NULL when the corresponding component is absent from the
 * input (except `file`, which is always set on success).
 */
typedef struct {
    const char *profile;    /* Profile name, or NULL if not specified */
    const char *file;       /* File path (always set on success) */
    const char *commit;     /* Commit reference, or NULL if not specified */
} refspec_t;

/**
 * Parse refspec: [profile:]<path>[@commit]
 *
 * Splits the input into profile, file path, and commit components.
 * The ':' separator for profile is optional (profile defaults to NULL).
 * The '@' separator is only recognized when followed by a valid git reference.
 *
 * Output slices are bump-allocated in the provided arena and share its
 * lifetime. On error, *out is left unchanged; callers should only read
 * *out after the returned error is NULL.
 *
 * Examples:
 *   "home/.bashrc"                  -> {NULL,         "home/.bashrc", NULL}
 *   "global:home/.bashrc"           -> {"global",     "home/.bashrc", NULL}
 *   "home/.bashrc@a4f2c8e"          -> {NULL,         "home/.bashrc", "a4f2c8e"}
 *   "home/.bashrc@HEAD~1"           -> {NULL,         "home/.bashrc", "HEAD~1"}
 *   "global:home/.bashrc@a4f2c8e"   -> {"global",     "home/.bashrc", "a4f2c8e"}
 *   "darwin/work:home/.bashrc"      -> {"darwin/work","home/.bashrc", NULL}
 *   "foo@bar.txt"                   -> {NULL,         "foo@bar.txt",  NULL}  (not a git ref)
 *
 * @param arena Arena for output allocations (must not be NULL).
 * @param input Refspec string (must not be NULL).
 * @param out   Parsed components. Untouched on error.
 * @return Error or NULL on success.
 */
error_t *parse_refspec(arena_t *arena, const char *input, refspec_t *out);

#endif /* DOTTA_REFSPEC_H */
