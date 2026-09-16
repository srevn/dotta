/**
 * ignore.c - Manage ignore patterns
 */

#include "cmds/ignore.h"

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "base/args.h"
#include "base/array.h"
#include "base/buffer.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/output.h"
#include "base/string.h"
#include "cmds/completion.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/editor.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/source.h"

/**
 * Does any line of content name the same rule as pattern? (zero-allocation)
 *
 * Rules, not text: the lines are read from where the file's begin, past a
 * byte-order mark at its head (gitignore_file_lines), each as base/gitignore
 * reads it, and two lines are one rule iff their spans are equal byte for byte —
 * so `foo` and `foo   ` are one rule while `foo` and `  foo` are two, and a
 * blank or comment line names none. `span` is the pattern's own, which the caller
 * has already asked for — never zero, since require_patterns refused every argument
 * that makes no rule. A span is the rule's identity, not its line: the caller
 * writes the pattern whole.
 */
static bool pattern_exists(const char *content, const char *pattern, size_t span) {
    const char *line = gitignore_file_lines(content);

    /* A line and its newline are one step; the last line needs no newline. */
    while (*line) {
        size_t len = strcspn(line, "\n");
        if (gitignore_rule_span(line, len) == span &&
            memcmp(line, pattern, span) == 0) {
            return true;
        }

        line += len + (line[len] == '\n');
    }

    return false;
}

/**
 * Refuse an argument that is not one pattern, before anything is read or written.
 *
 * The grammar's refusing verb reads each as the line it would be in the file: a
 * newline (two lines would land as two rules), an over-long line, and a line
 * that makes no rule — which would land as a comment or as nothing, reported as
 * "no changes" — are refused in its words, which quote the argument where its
 * words are the reason. The flag is named here.
 */
static error_t *require_patterns(const char *flag, char **patterns, size_t count) {
    for (size_t i = 0; i < count; i++) {
        error_t *err = gitignore_validate_pattern(patterns[i]);
        if (err) {
            return error_wrap(err, "Invalid %s pattern", flag);
        }
    }

    return NULL;
}

/**
 * Refuse a rule named by both --add and --remove, before the file is opened.
 *
 * The edit would write it and take it back — two receipts for a file that ends
 * as it began, or differs by a separator newline alone. Compared as rules, as
 * pattern_exists compares them: `--add foo --remove 'foo   '` names one rule.
 * Every span is nonzero here, since require_patterns refused the rest, and the
 * rule is quoted as written — its span, the spelling a verdict reports it under.
 */
static error_t *require_disjoint(
    char **add_patterns,
    size_t add_count,
    char **remove_patterns,
    size_t remove_count
) {
    for (size_t i = 0; i < add_count; i++) {
        const char *p = add_patterns[i];
        size_t span = gitignore_rule_span(p, strlen(p));

        for (size_t j = 0; j < remove_count; j++) {
            const char *q = remove_patterns[j];
            if (gitignore_rule_span(q, strlen(q)) == span &&
                memcmp(p, q, span) == 0) {
                return ERROR(
                    ERR_INVALID_ARG,
                    "Cannot use --add and --remove on one rule: '%.*s'",
                    (int) span, p
                );
            }
        }
    }

    return NULL;
}

/**
 * Add patterns to .dottaignore content
 *
 * Appends each pattern as it was given, and its newline — the line require_patterns
 * read it as, so the file reads back the rule the pattern was checked as — skipping
 * a pattern whose rule is already present, in the file or earlier in the batch.
 * Deduplication is by rule (pattern_exists), against the accumulating buffer.
 * The pattern, never its span: `foo<CR><SP>` is the rule foo<CR>, and its span
 * written back alone would be the rule foo.
 *
 * `existing_content` is the file as read, or the seed — never empty, since
 * ignore_blob_text answers an empty blob as absent and modify_dottaignore seeds
 * the absent one — so no pattern lands at the head of the file, where a byte-order
 * mark in front of it would be the file's and not the pattern's.
 *
 * Contract: on success, *new_content is NULL iff *added_count == 0. The helper
 * never hands back a buffer that is byte-identical to its input, so callers can
 * treat NULL as "nothing changed" without further checks.
 */
static error_t *add_patterns_to_content(
    const char *existing_content,
    char **patterns,
    size_t pattern_count,
    char **new_content,
    size_t *added_count
) {
    CHECK_NULL(existing_content);
    CHECK_NULL(patterns);
    CHECK_NULL(new_content);
    CHECK_NULL(added_count);

    *new_content = NULL;
    *added_count = 0;

    size_t existing_len = strlen(existing_content);

    /* Upper bound: as if every pattern were written */
    size_t max_size = existing_len + 1;      /* +1 for possible separator */
    for (size_t i = 0; i < pattern_count; i++) {
        max_size += strlen(patterns[i]) + 1; /* pattern + newline */
    }

    char *result = malloc(max_size + 1);  /* +1 for null terminator */
    if (!result) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate content buffer"
        );
    }

    /* Seed result with existing content, ended by a newline */
    memcpy(result, existing_content, existing_len);
    char *pos = result + existing_len;
    if (existing_content[existing_len - 1] != '\n') {
        *pos++ = '\n';
    }
    *pos = '\0';

    /*
     * Single pass: span, deduplicate, append.
     *
     * Checking pattern_exists() against the accumulated result buffer handles
     * both existing-content dedup and batch dedup in one call: previously appended
     * patterns are already in the buffer.
     */
    for (size_t i = 0; i < pattern_count; i++) {
        const char *p = patterns[i];
        size_t length = strlen(p);
        if (pattern_exists(result, p, gitignore_rule_span(p, length))) {
            continue;
        }

        memcpy(pos, p, length);
        pos += length;
        *pos++ = '\n';
        *pos = '\0';  /* Keep result valid for next pattern_exists call */
        (*added_count)++;
    }

    /* Nothing was added: the seeded buffer is a byte-for-byte copy of
     * existing_content. Drop it and signal "no change" via NULL so the caller
     * can skip a free(). */
    if (*added_count == 0) {
        free(result);
        return NULL;
    }

    *new_content = result;
    return NULL;
}

/**
 * Remove patterns from .dottaignore content
 *
 * Filters existing_content line-by-line, dropping every line that names the same
 * rule as an entry in patterns — equal spans, byte for byte, as pattern_exists
 * reads them; a blank or comment line names none and is always kept, and so are
 * the bytes before the first line (gitignore_file_lines), which are the file's.
 * Requests are counted by rule, as --add counts them: two that name one rule —
 * `foo` and `foo   ` — are one request, removed or not found once.
 * `*not_found_count` is always populated, whether or not the buffer changed.
 *
 * Contract: on success, *new_content is NULL iff *removed_count == 0. Callers
 * can treat NULL as "nothing changed" without a content compare.
 */
static error_t *remove_patterns_from_content(
    const char *existing_content,
    char **patterns,
    size_t pattern_count,
    char **new_content,
    size_t *removed_count,
    size_t *not_found_count
) {
    CHECK_NULL(existing_content);
    CHECK_NULL(patterns);
    CHECK_NULL(new_content);
    CHECK_NULL(removed_count);
    CHECK_NULL(not_found_count);

    *new_content = NULL;
    *removed_count = 0;
    *not_found_count = 0;

    /* The new content (the same size or smaller); each request's rule, its span
     * asked once and read on every line; and whether a line named it */
    char *result = malloc(strlen(existing_content) + 1);
    size_t *spans = calloc(pattern_count, sizeof(*spans));
    bool *found = calloc(pattern_count, sizeof(*found));
    if (!result || !spans || !found) {
        free(result);
        free(spans);
        free(found);
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }
    for (size_t i = 0; i < pattern_count; i++) {
        spans[i] = gitignore_rule_span(patterns[i], strlen(patterns[i]));
    }

    /* The lines begin where the grammar says, and the bytes before them — a
     * byte-order mark — are the file's: copied through whatever is removed behind
     * them, so removing the first rule never removes the mark, nor makes the
     * file's a mark the next line holds as pattern content. */
    const char *line = gitignore_file_lines(existing_content);
    size_t head = (size_t) (line - existing_content);
    memcpy(result, existing_content, head);
    char *pos = result + head;

    /* Line by line, zero-allocation: a line and its newline are one step, and
     * the last line needs no newline. */
    while (*line) {
        size_t len = strcspn(line, "\n");
        size_t step = len + (line[len] == '\n');
        size_t span = gitignore_rule_span(line, len);

        /* The first request that names this line's rule, in the order given. A
         * blank or comment line's span is zero, which no request's is:
         * require_patterns refused every argument that makes no rule. */
        size_t i;
        for (i = 0; i < pattern_count; i++) {
            if (spans[i] == span && memcmp(line, patterns[i], span) == 0) {
                break;
            }
        }

        if (i < pattern_count) {
            found[i] = true;
        } else {
            /* Not removed: kept as written (preserves original formatting) */
            memcpy(pos, line, step);
            pos += step;
        }

        line += step;
    }
    *pos = '\0';

    /* Counted by rule, as --add counts: a request naming the rule of an earlier
     * one is that request again — the walk marked the earlier — and is neither
     * removed nor missing a second time. */
    for (size_t i = 0; i < pattern_count; i++) {
        size_t first;
        for (first = 0; first < i; first++) {
            if (spans[first] == spans[i] &&
                memcmp(patterns[first], patterns[i], spans[i]) == 0) {
                break;
            }
        }
        if (first < i) {
            continue;
        }

        if (found[i]) {
            (*removed_count)++;
        } else {
            (*not_found_count)++;
        }
    }

    free(spans);
    free(found);

    /* No line matched — the seeded buffer would be identical to the input. Drop
     * it and signal "no change" via NULL so the caller can skip a free().
     * *not_found_count is still set above, so the "patterns not found" diagnostic
     * fires correctly. */
    if (*removed_count == 0) {
        free(result);
        return NULL;
    }

    *new_content = result;
    return NULL;
}

/**
 * Edit content in an external editor via a temporary file.
 *
 * Seeds a fresh mkstemp file with `seed` (may be empty when `seed_size == 0`),
 * launches the user's preferred editor via editor_launch_with_env (DOTTA_EDITOR
 * / VISUAL / EDITOR, falling back to `vi`), then reads the post-edit contents
 * into a heap-owned NUL-terminated buffer. The tempfile is unlinked on every
 * exit path.
 *
 * @param seed        Seed content (must not be NULL; may be empty)
 * @param seed_size   Bytes of seed to write (0 skips the write call)
 * @param out_content Receives heap-allocated NUL-terminated result (caller frees;
 *                    never NULL on success)
 * @param out_size    Receives byte count of result (excludes NUL)
 * @return Error or NULL on success
 */
static error_t *edit_content_via_editor(
    const char *seed,
    size_t seed_size,
    char **out_content,
    size_t *out_size
) {
    CHECK_NULL(seed);
    CHECK_NULL(out_content);
    CHECK_NULL(out_size);

    *out_content = NULL;
    *out_size = 0;

    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !*tmpdir) {
        tmpdir = "/tmp";
    }

    char *tmpfile = str_format("%s/dotta-ignore-XXXXXX", tmpdir);
    if (!tmpfile) {
        return ERROR(ERR_MEMORY, "Failed to allocate temporary file path");
    }

    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        free(tmpfile);
        return ERROR(ERR_FS, "Failed to create temporary file");
    }

    if (seed_size > 0) {
        ssize_t written = write(fd, seed, seed_size);
        if (written < 0 || (size_t) written != seed_size) {
            close(fd);
            unlink(tmpfile);
            free(tmpfile);
            return ERROR(ERR_FS, "Failed to write to temporary file");
        }
    }
    close(fd);

    error_t *err = editor_launch_with_env(tmpfile, "vi");
    if (err) {
        unlink(tmpfile);
        free(tmpfile);
        return err;
    }

    buffer_t content = BUFFER_INIT;
    err = fs_read_file(tmpfile, &content);
    unlink(tmpfile);
    free(tmpfile);
    if (err) {
        buffer_free(&content);
        return err;
    }

    *out_size = content.size;
    *out_content = buffer_detach(&content);
    if (!*out_content) {
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }
    return NULL;
}

/**
 * File-local scope for the two .dottaignore-editing surfaces: the baseline at
 * its own ref, and any named profile branch.
 *
 * Captures everything that differs between the two so edit_dottaignore and
 * modify_dottaignore stay ref-agnostic. Constructed on the stack in cmd_ignore;
 * the profile's refname and label live in that frame too.
 */
typedef struct {
    const char *refname;        /* BASELINE_REF or the profile's branch ref */
    const char *display_label;  /* "baseline" or "profile 'X'" */
    const char *default_seed;   /* default content / profile template */
} dottaignore_scope_t;

/**
 * Edit a .dottaignore via external editor.
 *
 * Called with scope->refname already verified to exist (cmd_ignore hoists that
 * check). Loads existing content, delegates to the editor helper, commits the
 * result back to the same ref.
 *
 * The bytes, not the text (ignore_blob_read): a human reads the file here, so a
 * .dottaignore every other reader refuses — one holding a NUL — opens as it stands,
 * to be mended. The write refuses what those readers would.
 */
static error_t *edit_dottaignore(
    git_repository *repo,
    const dottaignore_scope_t *scope,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(scope);

    char *existing_content = NULL;
    size_t existing_size = 0;
    error_t *err = ignore_blob_read(
        repo, scope->refname, &existing_content, &existing_size
    );
    if (err) {
        return error_wrap(
            err, "Failed to load %s .dottaignore", scope->display_label
        );
    }

    const char *seed;
    size_t seed_size;
    if (existing_content) {
        seed = existing_content;
        seed_size = existing_size;
    } else {
        seed = scope->default_seed;
        seed_size = strlen(seed);
    }

    char *new_content = NULL;
    size_t new_size = 0;
    err = edit_content_via_editor(
        seed, seed_size, &new_content, &new_size
    );
    if (err) {
        free(existing_content);
        return error_wrap(
            err, "Failed to edit %s .dottaignore", scope->display_label
        );
    }

    /* No-op detection: compare against the pre-edit blob. When the blob was absent
     * before the edit, any non-empty edit counts as a change (the editor only
     * produced content because the default seed was non-empty; a user who wiped
     * the buffer to empty still writes an empty blob intentionally). */
    bool unchanged = existing_content
        && new_size == existing_size
        && (new_size == 0 || memcmp(new_content, existing_content, new_size) == 0);
    free(existing_content);

    if (unchanged) {
        free(new_content);
        output_info(
            out, OUTPUT_NORMAL, "No changes to %s .dottaignore",
            scope->display_label
        );
        return NULL;
    }

    char *commit_msg = str_format(
        "Update %s .dottaignore", scope->display_label
    );
    if (!commit_msg) {
        free(new_content);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    err = ignore_blob_write(
        repo, scope->refname, new_content, new_size, commit_msg
    );
    free(commit_msg);
    free(new_content);

    if (err) {
        return error_wrap(
            err, "Failed to update %s .dottaignore", scope->display_label
        );
    }

    output_success(
        out, OUTPUT_NORMAL, "Updated %s .dottaignore", scope->display_label
    );
    return NULL;
}

/**
 * Add / remove patterns in a .dottaignore non-interactively.
 *
 * Called with scope->refname already verified to exist. Load existing content —
 * the text (ignore_blob_text), which the transforms read a line at a time — apply
 * add/remove transforms, commit the result if it actually changed.
 *
 * Ownership is linear: `owned` is the single buffer this function frees at every
 * exit. Each transform either leaves `owned` untouched (helper returned NULL =
 * no change) or hands back a fresh buffer we adopt after dropping the old one.
 * The helper contracts guarantee a non-NULL return iff the content actually
 * changed, which is what lets this function get by with one variable and no
 * pointer-identity comparisons.
 */
static error_t *modify_dottaignore(
    git_repository *repo,
    const dottaignore_scope_t *scope,
    char **add_patterns,
    size_t add_count,
    char **remove_patterns,
    size_t remove_count,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(scope);

    char *owned = NULL;
    error_t *err = ignore_blob_text(repo, scope->refname, &owned);
    if (err) {
        return error_wrap(
            err, "Failed to load %s .dottaignore", scope->display_label
        );
    }

    /* Nothing to work with: no existing file and no adds to seed one. Wording
     * uses "%s .dottaignore" so it composes naturally for both scopes: "No baseline
     * .dottaignore exists" / "No profile 'foo' .dottaignore exists". */
    if (!owned && add_count == 0) {
        output_info(
            out, OUTPUT_NORMAL, "No %s .dottaignore exists",
            scope->display_label
        );
        return NULL;
    }

    /* Seed with default/template when file is absent and adds exist. */
    if (!owned && add_count > 0) {
        owned = strdup(scope->default_seed);
        if (!owned) {
            return ERROR(ERR_MEMORY, "Failed to allocate default content");
        }
    }

    size_t total_added = 0;
    size_t total_removed = 0;
    size_t total_not_found = 0;

    if (add_count > 0) {
        size_t added = 0;
        char *next = NULL;
        err = add_patterns_to_content(
            owned, add_patterns, add_count, &next, &added
        );
        if (err) {
            free(owned);
            return error_wrap(err, "Failed to add patterns");
        }
        if (next) {
            free(owned);
            owned = next;
            total_added = added;
        }
    }

    if (remove_count > 0) {
        size_t removed = 0;
        size_t not_found = 0;
        char *next = NULL;
        err = remove_patterns_from_content(
            owned, remove_patterns, remove_count, &next, &removed, &not_found
        );
        if (err) {
            free(owned);
            return error_wrap(err, "Failed to remove patterns");
        }
        /* not_found is populated whether or not the buffer changed — always capture
         * so the "patterns not found" diagnostic fires even when nothing was
         * removed. */
        total_not_found = not_found;
        if (next) {
            free(owned);
            owned = next;
            total_removed = removed;
        }
    }

    /* Nothing actually changed — report why and return early. */
    if (total_added == 0 && total_removed == 0) {
        free(owned);

        if (add_count > 0 && remove_count > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "No changes: all patterns already exist or not found"
            );
        } else if (add_count > 0) {
            output_info(
                out, OUTPUT_NORMAL, "No changes: all patterns already exist"
            );
        } else {
            output_info(
                out, OUTPUT_NORMAL, "No changes: patterns not found"
            );
        }
        return NULL;
    }

    char *commit_msg = NULL;
    if (total_added > 0 && total_removed > 0) {
        commit_msg = str_format(
            "Update %s .dottaignore (added %zu, removed %zu patterns)",
            scope->display_label, total_added, total_removed
        );
    } else if (total_added > 0) {
        commit_msg = str_format(
            "Add %zu pattern%s to %s .dottaignore",
            total_added, total_added == 1 ? "" : "s", scope->display_label
        );
    } else {
        commit_msg = str_format(
            "Remove %zu pattern%s from %s .dottaignore",
            total_removed, total_removed == 1 ? "" : "s", scope->display_label
        );
    }

    if (!commit_msg) {
        free(owned);
        return ERROR(ERR_MEMORY, "Failed to allocate commit message");
    }

    err = ignore_blob_write(
        repo, scope->refname,
        owned, strlen(owned), commit_msg
    );

    free(commit_msg);
    free(owned);

    if (err) {
        return error_wrap(
            err, "Failed to update %s .dottaignore", scope->display_label
        );
    }

    if (total_added > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Added %zu pattern%s to %s .dottaignore",
            total_added, total_added == 1 ? "" : "s", scope->display_label
        );
    }
    if (total_removed > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Removed %zu pattern%s from %s .dottaignore",
            total_removed, total_removed == 1 ? "" : "s", scope->display_label
        );
    }
    if (total_not_found > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Warning: %zu pattern%s not found (already removed or never added)",
            total_not_found, total_not_found == 1 ? "" : "s"
        );
    }

    return NULL;
}

/**
 * Probe the source-tree .gitignore where no .dottaignore layer decided — the
 * lowest layer. Requires an absolute path; a NULL one (a custom/ storage path
 * with no target bound here) silently short-circuits to "no source verdict".
 *
 * Errors from the underlying libgit2 query are surfaced at NORMAL verbosity so
 * a --test invocation that can't probe layer 5 makes the limitation visible,
 * then return a "not excluded" verdict so the rest of the output remains coherent.
 */
static bool source_gitignore_matches(
    source_filter_t *filter,
    const char *abs_path,
    bool is_directory,
    output_t *out
) {
    if (!filter || !abs_path || abs_path[0] != '/') return false;

    bool excluded = false;
    error_t *err = source_filter_is_excluded(filter, abs_path, is_directory, &excluded);
    if (err) {
        output_warning(
            out, OUTPUT_NORMAL,
            "Source .gitignore check failed: %s", error_message(err)
        );
        error_free(err);
        return false;
    }
    return excluded;
}

/* The longest `who` an asker's line carries: "Profile '" (9), a profile name,
 * "': " (3) and the terminator, rounded. The name is bounded by the ref it becomes,
 * not by git's 255 — that one is per component and a profile name has several:
 * gitops_build_refname refuses a name that will not fit DOTTA_REFNAME_MAX after
 * "refs/heads/", and every site that turns a profile into a ref goes through it
 * (sys/gitops.h). */
#define IGNORE_ASKER_MAX 288

/**
 * The kind the rules are asked with: what stands where the argument stands.
 *
 * One lstat, the link itself and never its target — add's walk and the untracked
 * scan both classify this way and offer a symlink whole (cmds/add.c collect_tree,
 * core/workspace.c scan_directory_for_untracked), so a `pointer/` rule that does
 * not decide there must not decide here. A stat would follow the link, and a
 * broken one would read as absent; both are answers about something other than
 * the path.
 *
 * `location` is NULL for a custom/ name this asker binds no target for: the name
 * stands nowhere, so nothing can be looked at and the source tree has no path
 * to be asked about either. That, an absent path and an unreadable one are one
 * answer — the kind was not observed and the trailing-slash hint stands in, which
 * is what lets a rule be tested against a path that does not exist yet — and
 * each says which at VERBOSE, so a verdict that leaned on the hint says so. An
 * unreadable path is never reported as an absent one (sys/filesystem.h: a reader
 * must never infer absence from a failure to look).
 *
 * An observed leaf is a leaf whatever the hint says: `--test ~/foo/` where ~/foo
 * is a file is matched as a file.
 *
 * `who` names the asker whose reading this is, or is empty: a location is one
 * reading for every asker and is observed once, before the loop; a storage name
 * stands where each asker's own target puts it, and each says so in its own turn.
 * `typed` is the argument as the user wrote it — the only thing there is to name
 * when nothing stands anywhere for it to be.
 */
static bool stands_as_directory(
    const char *who,
    const char *typed,
    const char *location,
    bool trailing_slash,
    output_t *out
) {
    if (!location) {
        output_info(
            out, OUTPUT_VERBOSE,
            "%s'%s' has no deployment target here: only the name is matched",
            who, typed
        );
        return trailing_slash;
    }

    switch (fs_lstat_occupant(location, NULL)) {
        case FS_OCCUPANT_DIRECTORY:
            return true;

        case FS_OCCUPANT_REGULAR:
        case FS_OCCUPANT_SYMLINK:
        case FS_OCCUPANT_OTHER:
            return false;

        case FS_OCCUPANT_NONE:
            output_info(
                out, OUTPUT_VERBOSE, "%sPath does not exist: %s", who, location
            );
            break;

        case FS_OCCUPANT_UNKNOWN:
            output_info(
                out, OUTPUT_VERBOSE, "%sPath cannot be read: %s", who, location
            );
            break;
    }

    return trailing_slash;
}

/**
 * Test whether a path is ignored, one profile at a time
 *
 * The argument is one of the two keys a managed path has, and every profile the
 * verdict covers answers the other (infra/path.h — neither is manufactured from
 * the other); or it is the third key, which is no path and so gets no verdict:
 *
 *   - a storage path is the contract itself: its own tail is the subject, for
 *     every asker alike, and it stands wherever that asker's target puts it —
 *     so the location, and the kind and source verdict that follow from it, are
 *     read once per asker. Nothing here names anything, so no view is built: a
 *     literal name stays testable on a repository whose claim sheets will not load.
 *   - a filesystem path (absolute, tilde, relative, a bare name) is one location
 *     for every asker — the machine's reading, asked once — and each asker names
 *     it from its own claims and its own roots (core/manifest.h manifest_name):
 *     a directory the profile already tracks names what lies beneath it, and
 *     only where nothing of the profile's stands above the location do its roots
 *     answer. That is the whole reason a view is built here.
 *   - a label alone (`home/`) is a root, and a root has no name for a pattern
 *     to match. Every asker is told so in the noun its own table gives that root,
 *     and none casts a verdict — the same outcome the location spelling of a
 *     root reaches below, said without building a view for it.
 *
 * The *shape* is read by label_prefixes and not by the resolver, because a bare
 * name is a filesystem argument here — `dotta ignore --test foo.log` reads it
 * against the working directory, as add's grammar does — and path_input_resolve
 * refuses one, its callers' first positional being a profile. What the shape
 * dispatches to *is* the resolver for a storage spelling, which sheds the directory
 * slash and tells a name from a label; the filesystem arm is the normalizer alone,
 * whose answer is what the view's rows are keyed by too (infra/mount.h). Both
 * are read before the view is built, so a refusal is a plain return.
 *
 * The path need not exist: a trailing slash on one that does not is the directory
 * hint, so directory-only patterns (`cache/`) can be tested. The rules are
 * evaluated on the mount-relative subject, exactly as the walk evaluates them
 * (cmds/add.c is_excluded); the source tree's `.gitignore` is asked on the
 * location, when the asker has one, and only where no `.dottaignore` layer decided.
 *
 * The view is the named profile's branch at HEAD — which need not be enabled,
 * and answers when some *other* enabled profile's branch will not build — or
 * the enabled set's. Neither is declared: `ignore` is an editing command whose
 * other four surfaces must build nothing.
 *
 * A NULL name is a root of that asker with no claim standing on it — a root has
 * no canonical name and no pattern can match it — and is answered inside the
 * asker's own turn, the one place that can name the root a binding's own target
 * is. A label argument is that same answer known one question earlier, and takes
 * the same turn for the same reason. An asker that never got a subject cast no
 * verdict, which is why the summary reads two accumulators and not one: a path
 * no asker can name is neither ignored nor tracked.
 *
 * Cost: a filesystem argument pays a manifest build — a tree walk and a sheet
 * load per enabled profile — where it read the table alone. cmds/completion.c
 * already pays that on every tab press and records the measurement; a `--test`
 * invocation is not tighter than a completion. The other face of the same cost:
 * an enabled profile whose branch or sheet will not build refuses `--test` on a
 * filesystem argument, as it refuses status, apply and list. The named profile's
 * arm is insulated by construction, and a storage argument builds nothing.
 */
static error_t *test_path_ignore(
    const dotta_ctx_t *ctx,
    const char *test_path,
    const char *specific_profile
) {
    CHECK_NULL(ctx);
    CHECK_NULL(test_path);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* The directory hint is read from the argument as typed, and it is the only
     * thing read from it: both readings below shed a trailing slash of their
     * own — the resolver's storage arm sheds it, and fs_normalize_path folds it
     * away — so nothing here has to hand them a shortened copy. Shortening it
     * *before* the dispatch is what used to read `home/` as the working directory's
     * `home`. */
    size_t len = strlen(test_path);
    bool trailing_slash = len > 1 && test_path[len - 1] == '/';

    /* The profile named must be here before anything is read under it: the view
     * below is its branch, and the refusal names both ways out. */
    error_t *err = NULL;
    if (specific_profile) {
        err = profile_require(repo, specific_profile);
        if (err) return err;
    }

    /* What the cleanup releases, established before the first goto so the label
     * never reads an uninitialised one. */
    manifest_t *view = NULL;
    source_filter_t *source_filter = NULL;
    ignore_rules_t *ignore_rules = NULL;
    string_array_t *enabled = NULL;

    /* The key the user named, fixed for every asker: the resolver's sum, its
     * tag the whole condition the loop's arms read and its member the argument's
     * own reading. A second reading stands beside it where the key has one — a
     * name's tail, what the rules see; a location's kind, observed there once;
     * a root has none to make — so the loop reads what the argument gave and
     * asks nothing of it again. The table is the run's until a view is built,
     * and then the view's own — the one its rows were placed by. */
    const mount_table_t *mounts = ctx->run.mounts;
    path_input_t arg;                         /* the key: a name, a location or a root */
    const char *argument_subject = NULL;      /* a name's tail, what the rules see */
    bool argument_is_directory = false;       /* a location's kind, observed there once */

    if (label_prefixes(test_path)) {
        /* A storage shape, read by the one resolver that reads input shapes — a
         * name or a label alone and never a location, since the same predicate
         * dispatched here (cmds/add.c's storage head is the other). A bare name
         * never arrives: that is this command's own filesystem grammar, and the
         * predicate above let it past. */
        err = path_input_resolve(test_path, ctx->arena, &arg);
        if (err) return err;

        if (arg.key == PATH_KEY_STORAGE) {
            argument_subject = label_tail(arg.storage_path);
        }
    } else {
        /* The key as the location door spells it: absolute, folded, nothing read
         * through — the resolver's own location arm, read here because the resolver
         * refuses the bare name this grammar reads (infra/path.h
         * path_input_locate). */
        arg.key = PATH_KEY_LOCATION;
        err = path_input_locate(test_path, ctx->arena, &arg.location);
        if (err) {
            return error_wrap(err, "Failed to resolve path '%s'", test_path);
        }

        /* Both builders free their own partial view and leave *out NULL, so this
         * returns; from the build on, the view is owned and every failure leaves
         * by cleanup. */
        if (specific_profile) {
            err = manifest_build_branch(
                repo, specific_profile, mounts, ctx->arena, &view
            );
        } else {
            err = manifest_build(repo, state, ctx->arena, &view);
        }
        if (err) return err;

        /* The table the rows were placed by — the named profile's arm hands in
         * the very table this lends back (core/manifest.h manifest_mounts). */
        mounts = manifest_mounts(view);
    }

    /* Source .gitignore filter (opt-in via config). Built once for the whole
     * invocation so the discovered repo handle is reused across the loop. */
    if (config && config->respect_gitignore) {
        err = source_filter_create(&source_filter);
        if (err) {
            err = error_wrap(err, "Failed to build source .gitignore filter");
            goto cleanup;
        }
    }

    /* Layered-rules builder — the baseline compiled once, each profile's ruleset
     * composed on first request; no CLI layer, for --test takes no -e. */
    err = ignore_rules_create(repo, config, NULL, ctx->arena, &ignore_rules);
    if (err) {
        err = error_wrap(err, "Failed to build ignore rules");
        goto cleanup;
    }

    /* The askers: the profile named, the enabled set, or the one asker that is
     * no profile — which names through the shared roots and meets the baseline
     * and config layers alone. `askers` starts at the parameter itself, an array
     * of one that is both the named-profile and the nothing-enabled case; the
     * enabled set replaces it when there is one, and profile_resolve_enabled
     * never answers success with an empty one, so `enabled` is also what the
     * preamble and the summary key on. */
    const char *const *askers = &specific_profile;
    size_t asker_count = 1;

    if (!specific_profile) {
        err = profile_resolve_enabled(repo, state, &enabled);
        if (err) {
            if (error_code(err) != ERR_NOT_FOUND) {
                err = error_wrap(err, "Failed to load profiles");
                goto cleanup;
            }
            error_free(err);
            err = NULL;
        }

        if (enabled) {
            askers = (const char *const *) enabled->items;
            asker_count = enabled->count;
            output_info(out, OUTPUT_NORMAL, "Testing path: %s", test_path);
            output_info(out, OUTPUT_NORMAL, "Enabled profiles: %zu", asker_count);
            output_newline(out, OUTPUT_NORMAL);
        } else {
            output_info(out, OUTPUT_NORMAL, "No enabled profiles found");
            output_info(
                out, OUTPUT_NORMAL,
                "Testing against baseline .dottaignore and config patterns only"
            );
        }
    }

    /* The kind a filesystem argument is asked with: one reading for every asker,
     * so one observation and no asker to name it. Taken after the preamble rather
     * than where the key was read, so the note it may print stands under the
     * same header the per-asker notes of a storage name stand under — one command
     * saying one thing in one order. */
    if (arg.key == PATH_KEY_LOCATION) {
        argument_is_directory = stands_as_directory(
            "", test_path, arg.location, trailing_slash, out
        );
    }

    bool any_ignored = false;
    bool any_named = false;

    for (size_t i = 0; i < asker_count; i++) {
        const char *asker = askers[i];

        /* Whose answer this is, on every line of the turn. One value, so each
         * message below is spelled once and no site can forget the form the asker
         * that is no profile needs — the shape mount_root_describe already uses
         * for a root's noun. */
        char who[IGNORE_ASKER_MAX] = "";
        if (asker) {
            snprintf(who, sizeof(who), "Profile '%s': ", asker);
        }

        /* A label alone names this asker's root of that namespace, and a root
         * has no name for a pattern to match — the same answer, in the same words,
         * the location spelling of that place earns from the namer below, reached
         * one question earlier because a label needs no namer to say it. Said
         * per asker because the noun is the asker's; the verdict is not, so no
         * asker casts one and the summary reads what it reads for any unnameable
         * path. */
        if (arg.key == PATH_KEY_LABEL) {
            char buf[MOUNT_NOUN_MAX];
            output_info(
                out, OUTPUT_NORMAL,
                "%s'%s' is %s: it has no name for a pattern to match", who,
                test_path, mount_root_describe(arg.label, asker, buf, sizeof(buf))
            );
            continue;
        }

        /* The asker's reading, seeded with the key the user named: a storage
         * name is one subject for every asker alike, a location is the machine's
         * one reading and the kind observed there once. The arm fills the half
         * the argument did not name. */
        const char *subject = argument_subject;
        const char *location = arg.key == PATH_KEY_LOCATION ? arg.location : NULL;
        bool is_directory = argument_is_directory;

        if (arg.key == PATH_KEY_STORAGE) {
            /* Where this asker's target puts the name, and what stands there: a
             * custom/ name places only under a profile with a target. */
            err = mount_resolve(mounts, asker, arg.storage_path, ctx->arena, &location);
            if (err) goto cleanup;
            is_directory = stands_as_directory(
                who, test_path, location, trailing_slash, out
            );
        } else {
            /* What this asker calls the location: the claims it holds above it,
             * else its own roots. NULL is a root of this asker with no claim
             * standing on it — mount_name answered it, so mount_root writes the
             * label that describes it, and no pattern can match a root. */
            const char *name = NULL;
            err = manifest_name(view, asker, location, NULL, ctx->arena, &name);
            if (err) goto cleanup;
            if (!name) {
                label_t root;
                mount_root(mounts, asker, location, &root);
                char buf[MOUNT_NOUN_MAX];
                output_info(
                    out, OUTPUT_NORMAL,
                    "%s'%s' is %s: it has no name for a pattern to match",
                    who, test_path, mount_root_describe(root, asker, buf, sizeof(buf))
                );
                continue;
            }
            subject = label_tail(name);
        }
        any_named = true;

        output_info(
            out, OUTPUT_VERBOSE, "%sMatching '%s' as '%s'%s", who, test_path,
            subject, is_directory ? " (a directory)" : ""
        );

        const gitignore_ruleset_t *rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, asker, &rules);
        if (err) {
            err = error_wrap(err, "Failed to build ignore rules");
            goto cleanup;
        }

        /* The rules on the subject; where no layer decided, the source tree's
         * .gitignore on the location — the lowest layer, so a `!` above it wins. */
        gitignore_match_t match;
        gitignore_eval(rules, subject, is_directory, &match);
        bool ignored = match.decided
            ? match.ignored
            : source_gitignore_matches(source_filter, location, is_directory, out);

        if (ignored) {
            output_styled(out, OUTPUT_NORMAL, "{red}✗{reset} %sIGNORED\n", who);
            if (match.decided) {
                output_info(
                    out, OUTPUT_NORMAL, "  Reason: %s: '%s'",
                    ignore_origin_describe((ignore_origin_t) match.origin),
                    match.source
                );
            } else {
                output_info(out, OUTPUT_NORMAL, "  Reason: source .gitignore");
            }
            any_ignored = true;
        } else {
            output_success(out, OUTPUT_NORMAL, "%sNOT IGNORED", who);
        }
    }

    if (enabled) {
        output_newline(out, OUTPUT_NORMAL);
        if (any_ignored) {
            output_info(
                out, OUTPUT_NORMAL,
                "Result: Path would be IGNORED during add/update operations"
            );
        } else if (any_named) {
            output_success(out, OUTPUT_NORMAL, "Result: Path would be TRACKED");
        } else {
            output_info(
                out, OUTPUT_NORMAL,
                "Result: No enabled profile has a name for this path"
            );
        }
    }

cleanup:
    source_filter_free(source_filter);
    string_array_free(enabled);
    manifest_free(view);
    return err;
}

/**
 * Main command implementation
 */
error_t *cmd_ignore(const dotta_ctx_t *ctx, const cmd_ignore_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* --list-defaults is terminal: print the compiled defaults and exit.
     * Discoverability aid — lets users inspect the safety patterns without grepping
     * source or cloning the repo. */
    if (opts->list_defaults) {
        output_print(out, OUTPUT_NORMAL, "%s", ignore_baseline_defaults());
        return NULL;
    }

    bool has_add = opts->add_count > 0;
    bool has_remove = opts->remove_count > 0;
    bool has_test = opts->test_path != NULL;
    bool has_modify = has_add || has_remove;

    if (has_test && has_modify) {
        return ERROR(ERR_INVALID_ARG, "Cannot use --test with --add or --remove");
    }

    /* --test is a read-only query that walks every enabled profile by itself;
     * it doesn't use dottaignore_scope_t. Dispatch early. */
    if (has_test) {
        return test_path_ignore(ctx, opts->test_path, opts->profile);
    }

    /* A pattern is checked before its file is opened: an argument that names no
     * rule, or names two, is refused by name rather than written, and so is a
     * rule both added and removed, which the edit would write and take back. */
    RETURN_IF_ERROR(
        require_patterns("--add", opts->add_patterns, opts->add_count)
    );
    RETURN_IF_ERROR(
        require_patterns("--remove", opts->remove_patterns, opts->remove_count)
    );
    RETURN_IF_ERROR(
        require_disjoint(
        opts->add_patterns, opts->add_count,
        opts->remove_patterns, opts->remove_count
        )
    );

    /* The scope for edit / modify: the file's home, its name on the screen, and
     * what an editor opens on when the file is not there yet. Each arm establishes
     * its home before naming it — the profile named must be here, the baseline's
     * ref must stand — so edit and modify start on a ref that exists. The profile's
     * refname and label live in this frame. */
    char refname[DOTTA_REFNAME_MAX];
    char *profile_label = NULL;
    dottaignore_scope_t scope;
    error_t *err = NULL;
    if (opts->profile) {
        err = profile_require(repo, opts->profile);
        if (err) {
            return err;
        }
        err = gitops_branch_refname(refname, sizeof(refname), opts->profile);
        if (err) {
            return err;
        }
        profile_label = str_format("profile '%s'", opts->profile);
        if (!profile_label) {
            return ERROR(ERR_MEMORY, "Failed to format scope label");
        }
        scope = (dottaignore_scope_t){
            .refname = refname,
            .display_label = profile_label,
            .default_seed = ignore_profile_template(),
        };
    } else {
        /* Seeded by `dotta init` and `dotta clone`; absent only by hand, and
         * init is what puts it back. */
        bool seeded = false;
        err = gitops_reference_exists(repo, BASELINE_REF, &seeded);
        if (err) {
            return err;
        }
        if (!seeded) {
            return ERROR(
                ERR_NOT_FOUND,
                "No baseline .dottaignore: '%s' does not exist\n"
                "Run 'dotta init' to seed it with the default patterns",
                BASELINE_REF
            );
        }
        scope = (dottaignore_scope_t){
            .refname = BASELINE_REF,
            .display_label = "baseline",
            .default_seed = ignore_baseline_defaults(),
        };
    }

    if (has_modify) {
        err = modify_dottaignore(
            repo, &scope, opts->add_patterns, opts->add_count,
            opts->remove_patterns, opts->remove_count, out
        );
    } else {
        err = edit_dottaignore(repo, &scope, out);
    }

    free(profile_label);
    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * What can stand at the cursor: a local profile, by -p or as the one positional;
 * for --test, a filesystem path. Patterns are typed.
 */
static args_want_t ignore_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_ignore_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_ignore_options_t, profile)) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
        return ARGS_WANT_NONE;
    }
    if (ARGS_VALUE_IS(at, cmd_ignore_options_t, test_path)) {
        return ARGS_WANT_FILES;
    }
    if (at->value_of != NULL) {
        return ARGS_WANT_NONE;   /* --add, --remove: a pattern */
    }

    if (o->profile == NULL) {
        completion_profiles(ctx, out, COMPLETION_LOCAL);
    }
    return ARGS_WANT_NONE;
}

static error_t *ignore_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_ignore(ctx, (const cmd_ignore_options_t *) opts_v);
}

static const args_opt_t ignore_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_STRING(
        "p profile",         "<name>",
        cmd_ignore_options_t,profile,
        "Profile name (alternative to positional)"
    ),
    ARGS_APPEND(
        "add",               "<pattern>",
        cmd_ignore_options_t,add_patterns,    add_count,
        "Append pattern to .dottaignore (repeatable)"
    ),
    ARGS_APPEND(
        "remove",            "<pattern>",
        cmd_ignore_options_t,remove_patterns, remove_count,
        "Delete pattern from .dottaignore (repeatable)"
    ),
    ARGS_STRING(
        "test",              "<path>",
        cmd_ignore_options_t,test_path,
        "Report whether path is ignored"
    ),
    ARGS_FLAG(
        "list-defaults",
        cmd_ignore_options_t,list_defaults,
        "Print compiled default patterns and exit"
    ),
    ARGS_FLAG(
        "v verbose",
        cmd_ignore_options_t,verbose,
        "Verbose output (test mode: show matches)"
    ),
    ARGS_POSITIONAL_ANY_ARG(
        "[profile]",
        cmd_ignore_options_t,profile,         0,
        "Profile whose .dottaignore to use (default: the baseline)"
    ),
    ARGS_END,
};

const args_command_t spec_ignore = {
    .name        = "ignore",
    .summary     = "Manage ignore patterns",
    .usage       = "%s ignore [options] [profile]",
    .description =
        "View or edit .dottaignore files. Without a positional,\n"
        "operates on the machine-local baseline; with one, on that\n"
        "profile's .dottaignore which extends the baseline.\n",
    .notes       =
        "Ignore Pattern Layers (highest precedence first):\n"
        "  1. CLI --exclude patterns (per-operation)\n"
        "  2. Config file ignore patterns\n"
        "  3. Combined .dottaignore ruleset:\n"
        "     - Profile .dottaignore (synced with the profile)\n"
        "     - Baseline .dottaignore (machine-local)\n"
        "  4. Source .gitignore (lowest precedence)\n"
        "\n"
        "Pattern Subject:\n"
        "  A pattern is matched against the path as seen from the directory\n"
        "  it deploys under, as a .gitignore at ~, at / or at the deployment\n"
        "  target would match it: write .config/Code/Cache/ for\n"
        "  ~/.config/Code/Cache, never home/.\n"
        "  Run 'dotta ignore -v --test <path>' to see the exact subject.\n"
        "\n"
        "Pattern Syntax:\n"
        "  *.log                # Match all .log files\n"
        "  node_modules/        # Match directory\n"
        "  !debug.log           # Negate a prior match\n"
        "  .cache/              # Match .cache directories\n"
        "  /.cache/             # Match ~/.cache alone (anchored)\n"
        "\n"
        "Editor Selection:\n"
        "  $DOTTA_EDITOR, then $VISUAL, then $EDITOR, then vi\n",
    .examples    =
        "  %s ignore                                 # Edit baseline\n"
        "  %s ignore global                          # Edit profile file\n"
        "  %s ignore --add '*.tmp' --add '*.log'     # Append patterns\n"
        "  %s ignore global --remove '.DS_Store'     # Remove a pattern\n"
        "  %s ignore --add 'new' --remove 'old'      # Add + remove\n"
        "  %s ignore --list-defaults                 # Show compiled defaults\n"
        "  %s ignore --test ~/.config/nvim/node_modules  # Enabled profiles\n"
        "  %s ignore global --test ~/.bashrc         # Single profile\n"
        "  %s ignore --test home/.cache/x/           # A storage path, as a directory\n",
    .opts_size   = sizeof(cmd_ignore_options_t),
    .opts        = ignore_opts,
    .complete    = ignore_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
    },
    .dispatch    = ignore_dispatch,
};
