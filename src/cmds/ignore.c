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

#include "base/arena.h"
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
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/editor.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/source.h"

/**
 * Check if a pattern already exists in content (zero-allocation)
 *
 * Scans content line by line, trimming whitespace, then compares against the
 * given pattern using length + memcmp.  All non-empty lines are compared.
 * Pattern must already be normalized (no leading/trailing whitespace).
 */
static bool pattern_exists(const char *content, const char *pattern) {
    if (!content || !pattern) {
        return false;
    }

    size_t pat_len = strlen(pattern);
    if (pat_len == 0) {
        return false;
    }

    const char *line_start = content;

    while (*line_start) {
        /* Find end of line */
        const char *line_end = strchr(line_start, '\n');
        if (!line_end) {
            line_end = line_start + strlen(line_start);
        }

        /* Trim leading whitespace (no allocation) */
        const char *trim_start = line_start;
        size_t trim_len = (size_t) (line_end - line_start);

        while (trim_len > 0 && (*trim_start == ' ' || *trim_start == '\t')) {
            trim_start++;
            trim_len--;
        }

        /* Trim trailing whitespace */
        while (trim_len > 0) {
            char c = trim_start[trim_len - 1];
            if (c == ' ' || c == '\t' || c == '\r') {
                trim_len--;
            } else {
                break;
            }
        }

        /* Compare with pattern (skip empty lines) */
        if (trim_len > 0 && trim_len == pat_len &&
            memcmp(trim_start, pattern, pat_len) == 0) {
            return true;
        }

        /* Move to next line */
        if (*line_end == '\n') {
            line_start = line_end + 1;
        } else {
            break;
        }
    }

    return false;
}

/**
 * Normalize a pattern by trimming leading and trailing whitespace
 *
 * Returns pointer to the normalized pattern in the provided buffer, or NULL if
 * the pattern is empty/NULL after trimming.
 */
static const char *normalize_pattern(
    const char *pattern,
    char *buffer,
    size_t buffer_size,
    size_t *out_len
) {
    if (!pattern || *pattern == '\0') {
        return NULL;
    }

    /* Trim leading whitespace */
    while (*pattern == ' ' || *pattern == '\t') {
        pattern++;
    }
    if (*pattern == '\0') {
        return NULL;
    }

    /* Trim trailing whitespace */
    size_t len = strlen(pattern);
    while (len > 0 && (pattern[len - 1] == ' ' ||
        pattern[len - 1] == '\t' ||
        pattern[len - 1] == '\r')) {
        len--;
    }
    if (len == 0 || len >= buffer_size) {
        return NULL;
    }

    memcpy(buffer, pattern, len);
    buffer[len] = '\0';
    if (out_len) {
        *out_len = len;
    }

    return buffer;
}

/**
 * Add patterns to .dottaignore content
 *
 * Appends normalized patterns (whitespace-trimmed) to existing_content, skipping
 * patterns that already exist or are duplicates within the batch. Deduplication
 * is textual — each candidate is compared against lines already present in the
 * accumulating buffer.
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
    CHECK_NULL(patterns);
    CHECK_NULL(new_content);
    CHECK_NULL(added_count);

    *new_content = NULL;
    *added_count = 0;

    if (pattern_count == 0) {
        return NULL;
    }

    /* Calculate required buffer size */
    size_t existing_len = existing_content ? strlen(existing_content) : 0;

    /* Upper-bound allocation: normalization only trims, so raw lengths suffice */
    size_t max_size = existing_len + 1;  /* +1 for possible separator */
    for (size_t i = 0; i < pattern_count; i++) {
        if (patterns[i]) {
            max_size += strlen(patterns[i]) + 1;  /* pattern + newline */
        }
    }

    char *result = malloc(max_size + 1);  /* +1 for null terminator */
    if (!result) {
        return ERROR(
            ERR_MEMORY, "Failed to allocate content buffer"
        );
    }

    /* Seed result with existing content */
    char *pos = result;

    if (existing_content && existing_len > 0) {
        memcpy(pos, existing_content, existing_len);
        pos += existing_len;

        if (existing_content[existing_len - 1] != '\n') {
            *pos++ = '\n';
        }
    }
    *pos = '\0';

    /*
     * Single pass: normalize, deduplicate, append.
     *
     * Checking pattern_exists() against the accumulated result buffer handles
     * both existing-content dedup and batch dedup in one call: previously appended
     * patterns are already in the buffer.
     */
    for (size_t i = 0; i < pattern_count; i++) {
        char buf[4096];
        size_t plen;
        const char *p = normalize_pattern(
            patterns[i], buf, sizeof(buf), &plen
        );
        if (!p) continue;

        if (pattern_exists(result, p)) {
            continue;
        }

        memcpy(pos, p, plen);
        pos += plen;
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
 * Filters existing_content line-by-line, dropping any non-comment line that
 * textually matches a normalized entry in patterns. `*not_found_count` reports
 * how many requested patterns were absent from the input and is always populated
 * regardless of whether the buffer changed.
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
    CHECK_NULL(patterns);
    CHECK_NULL(new_content);
    CHECK_NULL(removed_count);
    CHECK_NULL(not_found_count);

    *new_content = NULL;
    *removed_count = 0;
    *not_found_count = 0;

    if (!existing_content || pattern_count == 0) {
        /* Nothing to filter: no new buffer produced. All requested patterns are
         * vacuously "not found" so the caller can report accurately. */
        *not_found_count = pattern_count;
        return NULL;
    }

    /* Create buffer for new content (same size or smaller) */
    size_t existing_len = strlen(existing_content);
    char *result = malloc(existing_len + 1);
    if (!result) {
        return ERROR(ERR_MEMORY, "Failed to allocate content buffer");
    }
    result[0] = '\0';

    /* Track which patterns were found */
    bool *pattern_found = calloc(pattern_count, sizeof(bool));
    if (!pattern_found) {
        free(result);
        return ERROR(ERR_MEMORY, "Failed to allocate pattern tracking");
    }

    /* Parse content line by line using zero-allocation approach */
    char *pos = result;
    const char *line_start = existing_content;

    while (*line_start) {
        /* Find end of line */
        const char *line_end = strchr(line_start, '\n');
        bool has_newline = (line_end != NULL);
        if (!line_end) {
            line_end = line_start + strlen(line_start);
        }

        /* Extract line */
        size_t line_len = (size_t) (line_end - line_start);

        /* Trim leading whitespace for comparison (no allocation) */
        const char *trim_start = line_start;
        size_t trim_len = line_len;

        while (trim_len > 0 && (*trim_start == ' ' || *trim_start == '\t')) {
            trim_start++;
            trim_len--;
        }

        /* Trim trailing whitespace */
        while (trim_len > 0) {
            char c = trim_start[trim_len - 1];
            if (c == ' ' || c == '\t' || c == '\r') {
                trim_len--;
            } else {
                break;
            }
        }

        /* Check if this line matches any pattern to remove */
        bool should_remove = false;
        if (trim_len > 0 && *trim_start != '#') {
            for (size_t i = 0; i < pattern_count; i++) {
                /* Normalize pattern for comparison */
                char pbuf[4096];
                size_t plen;
                const char *p = normalize_pattern(
                    patterns[i], pbuf, sizeof(pbuf), &plen
                );
                if (!p) continue;

                if (plen == trim_len && memcmp(trim_start, p, plen) == 0) {
                    should_remove = true;
                    pattern_found[i] = true;
                    break;
                }
            }
        }

        /* Keep line if not removing (preserves original formatting) */
        if (!should_remove) {
            memcpy(pos, line_start, line_len);
            pos += line_len;
            if (has_newline) {
                *pos++ = '\n';
            }
        }

        /* Move to next line */
        if (has_newline) {
            line_start = line_end + 1;
        } else {
            break;
        }
    }
    *pos = '\0';

    /* Count removed and not found */
    for (size_t i = 0; i < pattern_count; i++) {
        if (pattern_found[i]) {
            (*removed_count)++;
        } else {
            (*not_found_count)++;
        }
    }

    free(pattern_found);

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
 * Called with scope->refname already verified to exist. Load existing content,
 * apply add/remove transforms, commit the result if it actually changed.
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
    error_t *err = ignore_blob_read(
        repo, scope->refname, &owned, NULL
    );
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

/* The longest lead an asker's line carries: "Profile '" (9), a profile name (a
 * branch name — 255 bytes at git's limit), "': " and the terminator, rounded. */
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
 * the other):
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
 *
 * The shape is read by mount_spec_for_path and not by the resolver, for two
 * reasons. A bare name is a filesystem argument here — `dotta ignore --test
 * foo.log` reads it against the working directory, as add's grammar does — and
 * path_input_resolve refuses one, its callers' first positional being a profile.
 * And the resolver answers the shape and locates in one call, where the shape
 * is what says whether there is a view to locate through: the location has to
 * key against the view's rows by strcmp, and the rows were placed by the view's
 * own table (core/manifest.h manifest_mounts). The one question that can be asked
 * before the table is chosen is the pure label test, which touches none.
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
 * is. An asker that never got a subject cast no verdict, which is why the summary
 * reads two accumulators and not one: a path no asker can name is neither ignored
 * nor tracked.
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

    /* The directory hint is read before resolution: the storage grammar refuses
     * a trailing slash, and normalization drops it. */
    size_t len = strlen(test_path);
    bool trailing_slash = len > 1 && test_path[len - 1] == '/';
    const char *input = test_path;
    if (trailing_slash) {
        input = arena_strndup(ctx->arena, test_path, len - 1);
        if (!input) {
            return ERROR(ERR_MEMORY, "Failed to allocate path");
        }
    }

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

    /* The key the user named, fixed for every asker: exactly one of the two is
     * non-NULL, and which one is the whole condition the loop's arms read. The
     * table is the run's until a view is built, and then the view's own — the
     * one its rows were placed by. */
    const mount_table_t *mounts = ctx->run.mounts;
    const char *argument_name = NULL;        /* a storage argument: its own name */
    const char *argument_location = NULL;    /* a filesystem argument: where it stands */
    bool argument_is_directory = false;      /* … and the kind observed there, once */

    if (mount_spec_for_path(input)) {
        err = mount_validate_storage(input);
        if (err) {
            return error_wrap(err, "Invalid storage path '%s'", input);
        }
        argument_name = input;
    } else {
        /* Both builders free their own partial view and leave *out NULL, so this
         * returns; from the locate on, the view is owned and every failure leaves
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

        char *absolute = NULL;
        err = path_input_normalize(input, &absolute);
        if (err) {
            err = error_wrap(err, "Failed to resolve path '%s'", input);
            goto cleanup;
        }
        err = mount_locate(mounts, absolute, ctx->arena, &argument_location);
        free(absolute);
        if (err) goto cleanup;
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

    /* Layered-rules builder — baseline + config once, each profile's ruleset
     * memoised on first request. */
    err = ignore_rules_create(repo, config, NULL, 0, ctx->arena, &ignore_rules);
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

    /* The kind a located argument is asked with: one reading for every asker,
     * so one observation and no asker to name it. Taken after the preamble rather
     * than at the locate, so the note it may print stands under the same header
     * the per-asker notes of a storage name stand under — one command saying
     * one thing in one order. */
    if (argument_location) {
        argument_is_directory = stands_as_directory(
            "", test_path, argument_location, trailing_slash, out
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

        /* The asker's reading, seeded with the key the user named: a storage
         * name is one subject for every asker alike, a location is the machine's
         * one reading and the kind observed there once. The arm fills the half
         * the argument did not name. */
        const char *subject = mount_strip_label(argument_name);
        const char *location = argument_location;
        bool is_directory = argument_is_directory;

        if (argument_name) {
            /* Where this asker's target puts the name, and what stands there: a
             * custom/ name places only under a profile with a target. */
            err = mount_resolve(mounts, asker, argument_name, ctx->arena, &location);
            if (err) goto cleanup;
            is_directory = stands_as_directory(
                who, test_path, location, trailing_slash, out
            );
        } else {
            /* What this asker calls the location: the claims it holds above it,
             * else its own roots. NULL is a root of this asker with no claim
             * standing on it — mount_name answered it, so mount_root finds the
             * spec that describes it, and no pattern can match a root. */
            const char *name = NULL;
            err = manifest_name(view, asker, location, NULL, ctx->arena, &name);
            if (err) goto cleanup;
            if (!name) {
                char buf[MOUNT_NOUN_MAX];
                const char *noun = mount_root_describe(
                    mount_root(mounts, asker, location), asker, buf, sizeof(buf)
                );
                output_info(
                    out, OUTPUT_NORMAL,
                    "%s'%s' is %s: it has no name for a pattern to match",
                    who, test_path, noun
                );
                continue;
            }
            subject = mount_strip_label(name);
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
                    match.pattern
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
    ignore_rules_free(ignore_rules);
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
        "  A pattern is matched against the path relative to its mount root,\n"
        "  as a .gitignore at ~, at / or at the deployment target would match\n"
        "  it: write .config/Code/Cache/ for ~/.config/Code/Cache, never home/.\n"
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
