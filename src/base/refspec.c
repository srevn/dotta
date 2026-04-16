/**
 * refspec.c - Refspec parsing utilities
 *
 * Splits "[profile:]<path>[@commit]" into three slices with a single pass.
 * Allocation is polymorphic: either arena-backed (caller-supplied) or heap
 * (legacy contract, caller frees). See refspec.h for lifetime rules.
 *
 * When @arena is non-NULL, slices come from arena_strndup / arena_strdup;
 * when NULL, from the libc equivalents. Both report OOM by returning NULL,
 * which the caller maps onto ERR_MEMORY.
 */

#include "base/refspec.h"

#include <stdlib.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"
#include "base/string.h"

static char *rs_strndup(arena_t *arena, const char *src, size_t n) {
    return arena ? arena_strndup(arena, src, n) : strndup(src, n);
}

static char *rs_strdup(arena_t *arena, const char *src) {
    return arena ? arena_strdup(arena, src) : strdup(src);
}

/* Free a heap slice on error; no-op for arena-backed slices. */
static void rs_free(arena_t *arena, char *p) {
    if (!arena) free(p);
}

error_t *parse_refspec(
    arena_t *arena,
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

    /* Step 1: first ':' separates profile (permits sub-profile like darwin/work). */
    const char *colon = strchr(input, ':');
    const char *remainder = input;

    if (colon) {
        size_t profile_len = (size_t) (colon - input);
        if (profile_len > 0) {
            profile = rs_strndup(arena, input, profile_len);
            if (!profile) {
                err = ERROR(ERR_MEMORY, "Failed to allocate profile name");
                goto cleanup;
            }
        }
        remainder = colon + 1;
    }

    /* Step 2: last '@' separates commit, but only when the suffix is a git ref. */
    const char *at = strrchr(remainder, '@');

    if (at && at[1] != '\0' && str_looks_like_git_ref(at + 1)) {
        /* Valid git ref after @ - split into file and commit */
        size_t file_len = (size_t) (at - remainder);
        if (file_len == 0) {
            err = ERROR(ERR_INVALID_ARG, "Empty file path in refspec");
            goto cleanup;
        }

        file = rs_strndup(arena, remainder, file_len);
        if (!file) {
            err = ERROR(ERR_MEMORY, "Failed to allocate file path");
            goto cleanup;
        }

        commit = rs_strdup(arena, at + 1);
        if (!commit) {
            err = ERROR(ERR_MEMORY, "Failed to allocate commit reference");
            goto cleanup;
        }
    } else {
        /* No '@', empty suffix, or suffix isn't a git ref: whole remainder is the file. */
        file = rs_strdup(arena, remainder);
        if (!file) {
            err = ERROR(ERR_MEMORY, "Failed to allocate file path");
            goto cleanup;
        }
    }

    /* Transfer ownership to caller. Locals are nulled so cleanup is a no-op. */
    *out_profile = profile;
    *out_file = file;
    *out_commit = commit;
    profile = NULL;
    file = NULL;
    commit = NULL;

cleanup:
    /* Only heap slices need freeing. Arena-backed slices remain owned by the arena. */
    rs_free(arena, profile);
    rs_free(arena, file);
    rs_free(arena, commit);

    if (err) {
        *out_profile = NULL;
        *out_file = NULL;
        *out_commit = NULL;
    }
    return err;
}
