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
 * Parse refspec: [profile:]<path>[@commit]
 *
 * Extracts profile, file path, and commit from a refspec string.
 * The ':' separator for profile is optional (profile defaults to NULL).
 * The '@' separator is only recognized when followed by a valid git reference.
 *
 * Allocator selection:
 *   - When @arena is NULL, outputs are allocated with malloc/strdup.
 *     The caller owns each non-NULL output and must free() it.
 *   - When @arena is non-NULL, outputs are bump-allocated in the arena.
 *     The caller MUST NOT free() them — the arena owns their lifetime.
 *
 * All output parameters are set to NULL on error.
 *
 * Examples:
 *   "home/.bashrc"                  -> profile=NULL, file="home/.bashrc", commit=NULL
 *   "global:home/.bashrc"           -> profile="global", file="home/.bashrc", commit=NULL
 *   "home/.bashrc@a4f2c8e"          -> profile=NULL, file="home/.bashrc", commit="a4f2c8e"
 *   "home/.bashrc@HEAD~1"           -> profile=NULL, file="home/.bashrc", commit="HEAD~1"
 *   "global:home/.bashrc@a4f2c8e"   -> profile="global", file="home/.bashrc", commit="a4f2c8e"
 *   "darwin/work:home/.bashrc"      -> profile="darwin/work", file="home/.bashrc", commit=NULL
 *   "foo@bar.txt"                   -> profile=NULL, file="foo@bar.txt", commit=NULL (not a git ref)
 *
 * @param arena Optional arena for allocations (NULL = heap / caller frees).
 * @param input Refspec string (must not be NULL)
 * @param out_profile Profile name or NULL if not specified
 * @param out_file File path (always set on success)
 * @param out_commit Commit ref or NULL if not specified
 * @return Error or NULL on success
 */
error_t *parse_refspec(
    arena_t *arena,
    const char *input,
    char **out_profile,
    char **out_file,
    char **out_commit
);

#endif /* DOTTA_REFSPEC_H */
