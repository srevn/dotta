/**
 * label.c - The grammar of a storage name
 *
 * Traversal is refused at the boundary (label_validate_storage) and trusted below
 * it (infra/label.h, infra/mount.h).
 */

#include "infra/label.h"

#include <assert.h>
#include <string.h>

#include "base/arena.h"
#include "base/error.h"

/**
 * The word of each label — the single source of truth.
 *
 * Indexed by `label_t` and sized by the arity the header publishes, so the enum
 * declares the label set once and the array's extent is that declaration rather
 * than a second one that happens to agree. Designated initializers keep the words
 * in lockstep with the ordinals, which is what lets a reader subscript by the label
 * it holds; an entry left out is a NULL the walks below read, and the parse of
 * every word back to its own label is the only check an array's completeness can
 * have (tests/test-label.c).
 */
const char *const label_words[LABEL_COUNT] = {
    [LABEL_HOME] = "home", [LABEL_ROOT] = "root", [LABEL_CUSTOM] = "custom",
};

label_split_t label_split(const char *s) {
    if (!s) return (label_split_t){ 0 };

    for (label_t label = LABEL_HOME; label < LABEL_COUNT; label++) {
        const char *word = label_words[label];
        size_t word_len = strlen(word);

        if (strncmp(s, word, word_len) != 0) continue;
        if (s[word_len] != '/') continue;

        return (label_split_t){ .label = label, .tail = s + word_len + 1 };
    }

    return (label_split_t){ 0 };
}

bool label_prefixes(const char *s) {
    return label_split(s).tail != NULL;
}

label_t label_of(const char *storage_path) {
    label_split_t split = label_split(storage_path);

    /* The precondition (infra/label.h): a path under no label is a caller's bug,
     * and no label may stand in for it. */
    assert(split.tail);

    return split.label;
}

const char *label_tail(const char *storage_path) {
    label_split_t split = label_split(storage_path);

    /* label_of's precondition, the same way. */
    assert(split.tail);

    return split.tail;
}

bool label_parse(const char *word, label_t *out) {
    if (!word) return false;

    for (label_t label = LABEL_HOME; label < LABEL_COUNT; label++) {
        if (strcmp(word, label_words[label]) != 0) continue;
        if (out) *out = label;
        return true;
    }

    return false;
}

error_t *label_validate_storage(const char *storage_path) {
    CHECK_NULL(storage_path);

    if (storage_path[0] == '\0') {
        return ERROR(ERR_INVALID_ARG, "Storage path cannot be empty");
    }

    /* SECURITY: Reject absolute paths */
    if (storage_path[0] == '/') {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must be relative (got '%s')",
            storage_path
        );
    }

    /* SECURITY: Must start with home/, root/, or custom/. Asked beneath the two
     * above, which stand under no label either and would be told the wrong rule
     * by this one. */
    label_split_t split = label_split(storage_path);
    if (!split.tail) {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must start with "
            "'home/', 'root/', or 'custom/' (got '%s')", storage_path
        );
    }

    /* Must reference a file, not just a label directory */
    if (storage_path[strlen(storage_path) - 1] == '/') {
        return ERROR(
            ERR_INVALID_ARG, "Storage path must not end with '/': '%s'",
            storage_path
        );
    }

    /* Reject consecutive slashes */
    if (strstr(storage_path, "//") != NULL) {
        return ERROR(
            ERR_INVALID_ARG, "Invalid path format ('//'): '%s'",
            storage_path
        );
    }

    /* SECURITY: Tail components must not be `.` or `..`. A component is one by
     * its first bytes and whatever ends it, so the walk reads neither a length
     * nor a token; the label itself ("home"/"root"/"custom") is constant and never
     * a traversal token, so only the tail is walked. An empty component — the one
     * a `//` or a trailing `/` leaves — was refused above in its own words and
     * does not reach here. The message names the path the user typed, not the tail
     * it is walking. */
    for (const char *comp = split.tail; comp != NULL;) {
        if (comp[0] == '.' &&
            comp[1] == '.' && (comp[2] == '/' || comp[2] == '\0')) {
            return ERROR(
                ERR_INVALID_ARG, "Path traversal not allowed "
                "(component '..' in '%s')", storage_path
            );
        }
        if (comp[0] == '.' && (comp[1] == '/' || comp[1] == '\0')) {
            return ERROR(
                ERR_INVALID_ARG, "Invalid path component '.' in '%s'",
                storage_path
            );
        }

        const char *slash = strchr(comp, '/');
        comp = slash ? slash + 1 : NULL;
    }

    return NULL;
}

const char *label_compose(arena_t *arena, label_t label, const char *tail) {
    /* The write side of the rule the two projections assert: a label alone is no
     * storage name (infra/label.h). */
    assert(tail && *tail);

    return arena_str_format(arena, "%s/%s", label_words[label], tail);
}
