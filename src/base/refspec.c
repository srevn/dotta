/**
 * refspec.c - The commit a refspec carries, and the shape of a commit
 *
 * The one rule that says what a commit looks like, asked of the suffix after
 * each '@', from the last back, until one has a commit's shape: the commit a
 * token carries (refspec_commit), the one search the refspec's reading splits
 * at (infra/input.h input_refspec). See refspec.h for what that rule does and
 * does not recognize.
 */

#include "base/refspec.h"

#include <ctype.h>
#include <string.h>

bool refspec_looks_like_commit(const char *token) {
    if (!token || !*token) {
        return false;
    }

    /* HEAD's spellings, `@` among them: one rule for the lexer and the resolver */
    if (refspec_head_steps(token)) {
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

const char *refspec_head_steps(const char *spelling) {
    if (!spelling) {
        return NULL;
    }

    /* `@` is HEAD wherever it stands for it, as git reads it: alone the head
     * itself — the empty string the spelling ends with — or with a modifier right
     * after it (@~1, @^, @~3^2, @{1}, @:path), the reflog's `{` in the place
     * HEAD's `@{` takes. */
    if (spelling[0] == '@') {
        const char *steps = spelling + 1;
        if (steps[0] == '\0' || steps[0] == '~' || steps[0] == '^' ||
            steps[0] == '{' || steps[0] == ':') {
            return steps;
        }
        return NULL;
    }

    /* HEAD alone, or a modifier standing right after it (HEAD~1, HEAD^, HEAD~3^2,
     * HEAD@{1}, HEAD:path). The byte past the four is the whole of the rule — a
     * prefix test alone reads every word that begins with those letters as a
     * commit, and a profile named HEADER is not one — and it takes git's every
     * continuation of a name, so no spelling that opens on HEAD reaches git's
     * own, the store's. */
    if (strncmp(spelling, "HEAD", 4) != 0) {
        return NULL;
    }
    const char *steps = spelling + 4;
    if (steps[0] == '\0' || steps[0] == '~' || steps[0] == '^' ||
        steps[0] == '@' || steps[0] == ':') {
        return steps;
    }
    return NULL;
}

const char *refspec_commit(const char *token) {
    if (!token) {
        return NULL;
    }

    /* The shortest suffix with a commit's shape after an '@'. The last '@' is not
     * always the one: a commit may carry an '@' of its own — `@` alone, HEAD@{…}
     * — so `x@@` carries `@`, x at HEAD, and `x@HEAD@{1}` reaches the resolver's
     * refusal of a step it does not take instead of reading as a name that holds
     * it. */
    for (const char *p = token + strlen(token); p > token; p--) {
        if (p[-1] == '@' && refspec_looks_like_commit(p)) {
            return p;
        }
    }
    return NULL;
}
