/**
 * refspec.c - Refspec parsing utilities
 *
 * Splits "[profile:]<path>[@commit]" into three arena-backed slices, over the
 * one rule that says what a commit looks like — asked of the suffix after each
 * '@', from the last back, until one has a commit's shape. See refspec.h for
 * lifetime rules and for what that rule does and does not recognize.
 *
 * A partial parse that fails mid-way leaves a few unused bytes in the arena;
 * these are reclaimed when the arena is freed. No rollback is needed, so the
 * parse body is a straight sequence of returns.
 */

#include "base/refspec.h"

#include <ctype.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"

bool refspec_looks_like_commit(const char *token) {
    if (!token || !*token) {
        return false;
    }

    /* HEAD's spellings, `@` among them: one rule for the lexer and the resolver */
    if (refspec_ancestry(token)) {
        return true;
    }

    /* Check for pure commit SHA (7-40 hex chars) */
    size_t len = strlen(token);
    if (len >= 7 && len <= 40) {
        bool all_hex = true;
        for (size_t i = 0; i < len; i++) {
            if (!isxdigit((unsigned char) token[i])) {
                all_hex = false;
                break;
            }
        }
        if (all_hex) {
            return true;
        }
    }

    /* Check for SHA with modifiers (abc123^, def456~2, etc.) */
    const char *p = token;
    size_t hex_count = 0;

    /* Count leading hex chars */
    while (*p && isxdigit((unsigned char) *p)) {
        hex_count++;
        p++;
    }

    /* If we have 7+ hex chars followed by ~ or ^, it's a ref */
    if (hex_count >= 7 && (*p == '~' || *p == '^')) {
        return true;
    }

    return false;
}

const char *refspec_ancestry(const char *spelling) {
    if (!spelling) {
        return NULL;
    }

    /* `@` is HEAD wherever it stands for it, as git reads it: alone the tip itself
     * — the empty string the spelling ends with — or with a modifier right after
     * it (@~1, @^, @~3^2, @{1}), the reflog's `{` in the place HEAD's `@{`
     * takes. */
    if (spelling[0] == '@') {
        const char *steps = spelling + 1;
        if (steps[0] == '\0' || steps[0] == '~' || steps[0] == '^' || steps[0] == '{') {
            return steps;
        }
        return NULL;
    }

    /* HEAD alone, or a modifier standing right after it (HEAD~1, HEAD^, HEAD~3^2,
     * HEAD@{1}). The byte past the four is the whole of the rule — a prefix test
     * alone reads every word that begins with those letters as a commit, and a
     * profile named HEADER is not one. */
    if (strncmp(spelling, "HEAD", 4) != 0) {
        return NULL;
    }
    const char *steps = spelling + 4;
    if (steps[0] == '\0' || steps[0] == '~' || steps[0] == '^' || steps[0] == '@') {
        return steps;
    }
    return NULL;
}

error_t refspec_parse(arena_t *arena, const char *input, refspec_t *out) {
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
        }
        remainder = colon + 1;
    }

    /* Step 2: the commit is the shortest suffix after an '@' that has a commit's
     * shape. The last '@' is not always the one: a commit may carry an '@' of
     * its own — `@` alone, HEAD@{…} — so `x@@` is x at HEAD, and `x@HEAD@{1}`
     * reaches the resolver's refusal of a step it does not take instead of reading
     * as a file whose name holds it. */
    const char *at = NULL;
    for (const char *p = remainder + strlen(remainder); p > remainder; p--) {
        if (p[-1] == '@' && refspec_looks_like_commit(p)) {
            at = p - 1;
            break;
        }
    }

    if (at) {
        size_t file_len = (size_t) (at - remainder);
        if (file_len == 0) {
            return ERROR(ERR_INVALID_ARG, "Empty file path in refspec");
        }

        rs.file = arena_strndup(arena, remainder, file_len);
        rs.commit = arena_strdup(arena, at + 1);
    } else {
        /* No '@' with a commit after it: the whole remainder is the file. */
        rs.file = arena_strdup(arena, remainder);
    }

    *out = rs;
    return NULL;
}
