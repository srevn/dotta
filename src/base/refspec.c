/**
 * refspec.c - Refspec parsing utilities
 *
 * Splits "[profile:]<path>[@commit]" into three arena-backed slices
 * in a single pass. See refspec.h for lifetime rules.
 *
 * A partial parse that fails mid-way leaves a few unused bytes in the
 * arena; these are reclaimed when the arena is destroyed. No rollback
 * is needed, so the parse body is a straight sequence of returns.
 */

#include "base/refspec.h"

#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"

error_t *parse_refspec(arena_t *arena, const char *input, refspec_t *out) {
    CHECK_NULL(arena);
    CHECK_NULL(input);
    CHECK_NULL(out);

    refspec_t rs = { 0 };

    /* Step 1: first ':' separates profile (permits sub-profile like darwin/work). */
    const char *colon = strchr(input, ':');
    const char *remainder = input;

    if (colon) {
        size_t profile_len = (size_t) (colon - input);
        if (profile_len > 0) {
            rs.profile = arena_strndup(arena, input, profile_len);
            if (!rs.profile) {
                return ERROR(ERR_MEMORY, "Failed to allocate profile name");
            }
        }
        remainder = colon + 1;
    }

    /* Step 2: last '@' separates commit, but only when the suffix is a git ref. */
    const char *at = strrchr(remainder, '@');
    if (at && at[1] != '\0' && str_looks_like_git_ref(at + 1)) {
        size_t file_len = (size_t) (at - remainder);
        if (file_len == 0) {
            return ERROR(ERR_INVALID_ARG, "Empty file path in refspec");
        }

        rs.file = arena_strndup(arena, remainder, file_len);
        if (!rs.file) {
            return ERROR(ERR_MEMORY, "Failed to allocate file path");
        }

        rs.commit = arena_strdup(arena, at + 1);
        if (!rs.commit) {
            return ERROR(ERR_MEMORY, "Failed to allocate commit reference");
        }
    } else {
        /* No '@', empty suffix, or suffix isn't a git ref: whole remainder is the file. */
        rs.file = arena_strdup(arena, remainder);
        if (!rs.file) {
            return ERROR(ERR_MEMORY, "Failed to allocate file path");
        }
    }

    *out = rs;
    return NULL;
}
