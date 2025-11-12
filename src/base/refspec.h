/**
 * refspec.h - Refspec parsing utilities
 *
 * Provides parsing for the refspec syntax: [profile:]<path>[@commit]
 * Used by commands that need to reference files with optional profile/commit context.
 */

#ifndef DOTTA_UTILS_REFSPEC_H
#define DOTTA_UTILS_REFSPEC_H

#include <types.h>

/**
 * Parse refspec: [profile:]<path>[@commit]
 *
 * Extracts profile, file path, and commit from refspec string.
 * The ':' separator for profile is optional (profile defaults to NULL).
 * The '@' separator is only recognized when followed by a valid git reference.
 *
 * All output parameters are set to NULL on error.
 * Caller must free all non-NULL output strings.
 *
 * Examples:
 *   "home/.bashrc"                  → profile=NULL, file="home/.bashrc", commit=NULL
 *   "global:home/.bashrc"           → profile="global", file="home/.bashrc", commit=NULL
 *   "home/.bashrc@a4f2c8e"          → profile=NULL, file="home/.bashrc", commit="a4f2c8e"
 *   "home/.bashrc@HEAD~1"           → profile=NULL, file="home/.bashrc", commit="HEAD~1"
 *   "global:home/.bashrc@a4f2c8e"   → profile="global", file="home/.bashrc", commit="a4f2c8e"
 *   "darwin/work:home/.bashrc"      → profile="darwin/work", file="home/.bashrc", commit=NULL
 *   "foo@bar.txt"                   → profile=NULL, file="foo@bar.txt", commit=NULL (not a git ref)
 *
 * @param input Refspec string (must not be NULL)
 * @param out_profile Profile name or NULL if not specified (caller must free)
 * @param out_file File path (always set if success, caller must free)
 * @param out_commit Commit ref or NULL if not specified (caller must free)
 * @return Error or NULL on success
 */
error_t *parse_refspec(
    const char *input,
    char **out_profile,
    char **out_file,
    char **out_commit
);

#endif /* DOTTA_UTILS_REFSPEC_H */
