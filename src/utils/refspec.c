/**
 * refspec.c - Refspec parsing utilities
 */

#include "refspec.h"

#include <stdlib.h>
#include <string.h>

#include "base/error.h"

/**
 * Parse refspec: [profile:]<path>[@commit]
 *
 * Extracts profile, file path, and commit from refspec string.
 * All output parameters are set to NULL on error.
 * Caller must free all non-NULL output strings.
 *
 * Examples:
 *   "home/.bashrc"                  → profile=NULL, file="home/.bashrc", commit=NULL
 *   "global:home/.bashrc"           → profile="global", file="home/.bashrc", commit=NULL
 *   "home/.bashrc@a4f2c8e"          → profile=NULL, file="home/.bashrc", commit="a4f2c8e"
 *   "global:home/.bashrc@a4f2c8e"   → profile="global", file="home/.bashrc", commit="a4f2c8e"
 *   "darwin/work:home/.bashrc"      → profile="darwin/work", file="home/.bashrc", commit=NULL
 */
error_t *parse_refspec(
    const char *input,
    char **out_profile,
    char **out_file,
    char **out_commit
) {
    CHECK_NULL(input);
    CHECK_NULL(out_profile);
    CHECK_NULL(out_file);
    CHECK_NULL(out_commit);

    error_t *err = NULL;
    char *profile = NULL;
    char *file = NULL;
    char *commit = NULL;

    /* Step 1: Find FIRST ':' for profile (handles sub-profiles like darwin/work) */
    const char *colon = strchr(input, ':');
    const char *remainder = input;

    if (colon) {
        size_t profile_len = colon - input;
        if (profile_len > 0) {
            profile = strndup(input, profile_len);
            if (!profile) {
                err = ERROR(ERR_MEMORY, "Failed to allocate profile name");
                goto cleanup;
            }
        }
        remainder = colon + 1;
    }

    /* Step 2: Find LAST '@' for commit (handles '@' in filenames) */
    const char *at = strrchr(remainder, '@');

    if (at) {
        /* Extract file path */
        size_t file_len = at - remainder;
        if (file_len == 0) {
            err = ERROR(ERR_INVALID_ARG, "Empty file path in refspec");
            goto cleanup;
        }

        file = strndup(remainder, file_len);
        if (!file) {
            err = ERROR(ERR_MEMORY, "Failed to allocate file path");
            goto cleanup;
        }

        /* Extract commit */
        const char *commit_str = at + 1;
        if (strlen(commit_str) == 0) {
            err = ERROR(ERR_INVALID_ARG, "Empty commit in refspec");
            goto cleanup;
        }

        commit = strdup(commit_str);
        if (!commit) {
            err = ERROR(ERR_MEMORY, "Failed to allocate commit");
            goto cleanup;
        }
    } else {
        /* No commit, just file */
        file = strdup(remainder);
        if (!file) {
            err = ERROR(ERR_MEMORY, "Failed to allocate file path");
            goto cleanup;
        }
    }

    /* Success - transfer ownership */
    *out_profile = profile;
    *out_file = file;
    *out_commit = commit;
    profile = NULL;
    file = NULL;
    commit = NULL;

cleanup:
    free(profile);
    free(file);
    free(commit);
    if (err) {
        *out_profile = NULL;
        *out_file = NULL;
        *out_commit = NULL;
    }
    return err;
}
