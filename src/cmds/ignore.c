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
#include "core/ignore.h"
#include "core/profiles.h"
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
 * Returns pointer to the normalized pattern in the provided buffer,
 * or NULL if the pattern is empty/NULL after trimming.
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
 * Appends normalized patterns (whitespace-trimmed) to existing_content,
 * skipping patterns that already exist or are duplicates within the batch.
 * Deduplication is textual — each candidate is compared against lines
 * already present in the accumulating buffer.
 *
 * Contract: on success, *new_content is NULL iff *added_count == 0. The
 * helper never hands back a buffer that is byte-identical to its input,
 * so callers can treat NULL as "nothing changed" without further checks.
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
     * Checking pattern_exists() against the accumulated result buffer
     * handles both existing-content dedup and batch dedup in one call:
     * previously appended patterns are already in the buffer.
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
     * existing_content. Drop it and signal "no change" via NULL so the
     * caller can skip a free(). */
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
 * Filters existing_content line-by-line, dropping any non-comment line
 * that textually matches a normalized entry in patterns. `*not_found_count`
 * reports how many requested patterns were absent from the input and is
 * always populated regardless of whether the buffer changed.
 *
 * Contract: on success, *new_content is NULL iff *removed_count == 0.
 * Callers can treat NULL as "nothing changed" without a content compare.
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
        /* Nothing to filter: no new buffer produced. All requested
         * patterns are vacuously "not found" so the caller can report
         * accurately. */
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

    /* No line matched — the seeded buffer would be identical to the input.
     * Drop it and signal "no change" via NULL so the caller can skip a
     * free(). *not_found_count is still set above, so the "patterns not
     * found" diagnostic fires correctly. */
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
 * Seeds a fresh mkstemp file with `seed` (may be empty when
 * `seed_size == 0`), launches the user's preferred editor via
 * editor_launch_with_env (DOTTA_EDITOR / VISUAL / EDITOR, falling
 * back to `vi`), then reads the post-edit contents into a
 * heap-owned NUL-terminated buffer. The tempfile is unlinked on
 * every exit path.
 *
 * @param seed        Seed content (must not be NULL; may be empty)
 * @param seed_size   Bytes of seed to write (0 skips the write call)
 * @param out_content Receives heap-allocated NUL-terminated result
 *                    (caller frees; never NULL on success)
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
 * File-local scope for the two .dottaignore-editing surfaces: the
 * baseline on dotta-worktree, and any named profile branch.
 *
 * Captures everything that differs between the two so edit_dottaignore
 * and modify_dottaignore stay branch-agnostic. Constructed on the
 * stack in cmd_ignore; label strings for the profile case are heap-
 * owned with matching cmd_ignore lifetime.
 */
typedef struct {
    const char *branch_name;    /* "dotta-worktree" or profile name */
    const char *display_label;  /* "baseline" or "profile 'X'" */
    const char *default_seed;   /* default content / profile template */
} dottaignore_scope_t;

/**
 * Edit a .dottaignore via external editor.
 *
 * Called with scope->branch_name already verified to exist (cmd_ignore
 * hoists that check). Loads existing content, delegates to the editor
 * helper, commits the result back to the same branch.
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
        repo, scope->branch_name, &existing_content, &existing_size
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

    /* No-op detection: compare against the pre-edit blob. When the
     * blob was absent before the edit, any non-empty edit counts as a
     * change (the editor only produced content because the default
     * seed was non-empty; a user who wiped the buffer to empty still
     * writes an empty blob intentionally). */
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
        repo, scope->branch_name, new_content, new_size, commit_msg
    );
    free(commit_msg);
    free(new_content);

    if (err) {
        return error_wrap(
            err, "Failed to update %s .dottaignore", scope->display_label
        );
    }

    /* INDEX and workdir are kept in sync by ignore_blob_write for the
     * current-branch case — no explicit worktree sync needed here. */

    output_success(
        out, OUTPUT_NORMAL, "Updated %s .dottaignore", scope->display_label
    );
    return NULL;
}

/**
 * Add / remove patterns in a .dottaignore non-interactively.
 *
 * Called with scope->branch_name already verified to exist. Load
 * existing content, apply add/remove transforms, commit the result
 * if it actually changed.
 *
 * Ownership is linear: `owned` is the single buffer this function frees
 * at every exit. Each transform either leaves `owned` untouched (helper
 * returned NULL = no change) or hands back a fresh buffer we adopt after
 * dropping the old one. The helper contracts guarantee a non-NULL return
 * iff the content actually changed, which is what lets this function
 * get by with one variable and no pointer-identity comparisons.
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
        repo, scope->branch_name, &owned, NULL
    );
    if (err) {
        return error_wrap(
            err, "Failed to load %s .dottaignore", scope->display_label
        );
    }

    /* Nothing to work with: no existing file and no adds to seed one.
     * Wording uses "%s .dottaignore" so it composes naturally for both
     * scopes: "No baseline .dottaignore exists" / "No profile 'foo'
     * .dottaignore exists". */
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
        /* not_found is populated whether or not the buffer changed — always
         * capture so the "patterns not found" diagnostic fires even when
         * nothing was removed. */
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
        repo, scope->branch_name,
        owned, strlen(owned), commit_msg
    );

    free(commit_msg);
    free(owned);

    if (err) {
        return error_wrap(
            err, "Failed to update %s .dottaignore", scope->display_label
        );
    }

    /* INDEX and workdir are kept in sync by ignore_blob_write for the
     * current-branch case — no explicit worktree sync needed here. */

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
 * Probe the source-tree .gitignore after the .dottaignore layers have
 * returned "not ignored". Requires an absolute path; a relative test
 * target (typical when the user types a non-existent relative path)
 * silently short-circuits to "no source verdict".
 *
 * Errors from the underlying libgit2 query are surfaced at NORMAL
 * verbosity so a --test invocation that can't probe layer 5 makes the
 * limitation visible, then return a "not excluded" verdict so the
 * rest of the output remains coherent.
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

/**
 * Test if path is ignored across profiles
 */
static error_t *test_path_ignore(
    git_repository *repo,
    const state_t *state,
    const config_t *config,
    const char *test_path,
    const char *specific_profile,
    arena_t *arena,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(state);
    CHECK_NULL(test_path);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Check if path exists and determine if it's a directory */
    bool path_exists = fs_exists(test_path);
    bool is_directory = false;

    if (path_exists) {
        is_directory = fs_is_directory(test_path);
    } else {
        /* For non-existent paths, treat trailing / as directory hint
         * so directory-only patterns (e.g., "cache/") can be tested */
        size_t len = strlen(test_path);
        is_directory = (len > 0 && test_path[len - 1] == '/');
    }

    /* Resolve relative paths to absolute so the source-tree check below
     * can discover the enclosing git repository. Non-existent paths are
     * left as-is — there is no filesystem location to resolve — and the
     * source check short-circuits on their relative form. */
    char resolved_buf[4096];
    const char *effective_path = test_path;

    if (test_path[0] != '/' && path_exists) {
        if (realpath(test_path, resolved_buf)) {
            effective_path = resolved_buf;
        }
    }

    if (!path_exists) {
        output_info(out, OUTPUT_VERBOSE, "Path does not exist: %s", test_path);
    }

    /* Source .gitignore filter (opt-in via config). Built once for the
     * whole test invocation so the discovered repo handle is reused
     * across the per-profile loop below. */
    source_filter_t *source_filter = NULL;
    if (config && config->respect_gitignore) {
        error_t *sf_err = source_filter_create(&source_filter);
        if (sf_err) {
            return error_wrap(sf_err, "Failed to build source .gitignore filter");
        }
    }

    /* Layered-rules builder — loads baseline + config once, memoises
     * each profile's ruleset on first request. */
    ignore_rules_t *ignore_rules = NULL;
    error_t *err = ignore_rules_create(
        repo, config, NULL, 0, arena, &ignore_rules
    );
    if (err) {
        source_filter_free(source_filter);
        return error_wrap(err, "Failed to build ignore rules");
    }

    string_array_t *profiles = NULL;

    /* If specific profile requested, test only that one */
    if (specific_profile) {
        if (!profile_exists(repo, specific_profile)) {
            err = ERROR(
                ERR_NOT_FOUND, "Profile '%s' does not exist", specific_profile
            );
            goto cleanup;
        }

        const gitignore_ruleset_t *rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, specific_profile, &rules);
        if (err) {
            err = error_wrap(
                err, "Failed to load ignore rules for profile '%s'",
                specific_profile
            );
            goto cleanup;
        }

        gitignore_match_t match;
        gitignore_eval(rules, effective_path, is_directory, &match);

        if (match.decided && match.ignored) {
            output_styled(
                out, OUTPUT_NORMAL, "{red}✗{reset} IGNORED by profile '%s'\n",
                specific_profile
            );
            output_info(
                out, OUTPUT_NORMAL, "  Reason: %s",
                ignore_origin_describe((ignore_origin_t) match.origin)
            );
        } else if (source_gitignore_matches(
            source_filter, effective_path, is_directory, out
            )) {
            output_styled(
                out, OUTPUT_NORMAL, "{red}✗{reset} IGNORED by profile '%s'\n",
                specific_profile
            );
            output_info(
                out, OUTPUT_NORMAL, "  Reason: source .gitignore"
            );
        } else {
            output_success(
                out, OUTPUT_NORMAL, "Not ignored by profile '%s'",
                specific_profile
            );
        }

        goto cleanup;
    }

    /* Test against all enabled profiles */
    err = profile_resolve_enabled(repo, state, &profiles);

    if (err) {
        if (error_code(err) != ERR_NOT_FOUND) {
            err = error_wrap(err, "Failed to load profiles");
            goto cleanup;
        }
        error_free(err);
        err = NULL;

        /* No enabled profiles - test against baseline + config only.
         * `ignore_rules_for_profile(..., NULL, ...)` returns the
         * ruleset with no per-profile layer. */
        output_info(
            out, OUTPUT_NORMAL, "No enabled profiles found"
        );
        output_info(
            out, OUTPUT_NORMAL,
            "Testing against baseline .dottaignore and config patterns only"
        );

        const gitignore_ruleset_t *rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, NULL, &rules);
        if (err) {
            err = error_wrap(err, "Failed to build ignore rules");
            goto cleanup;
        }

        gitignore_match_t match;
        gitignore_eval(rules, effective_path, is_directory, &match);

        if (match.decided && match.ignored) {
            output_styled(out, OUTPUT_NORMAL, "{red}✗{reset} IGNORED\n");
            output_info(
                out, OUTPUT_NORMAL, "  Reason: %s",
                ignore_origin_describe((ignore_origin_t) match.origin)
            );
        } else if (source_gitignore_matches(
            source_filter, effective_path, is_directory, out
            )) {
            output_styled(out, OUTPUT_NORMAL, "{red}✗{reset} IGNORED\n");
            output_info(
                out, OUTPUT_NORMAL, "  Reason: source .gitignore"
            );
        } else {
            output_success(out, OUTPUT_NORMAL, "Not ignored");
        }

        goto cleanup;
    }

    /* Test against each enabled profile */
    output_info(out, OUTPUT_NORMAL, "Testing path: %s", test_path);
    output_info(out, OUTPUT_NORMAL, "Enabled profiles: %zu", profiles->count);
    output_newline(out, OUTPUT_NORMAL);

    bool any_ignored = false;
    for (size_t i = 0; i < profiles->count; i++) {
        const char *profile = profiles->items[i];

        const gitignore_ruleset_t *rules = NULL;
        err = ignore_rules_for_profile(ignore_rules, profile, &rules);
        if (err) {
            err = error_wrap(
                err, "Failed to load ignore rules for profile '%s'", profile
            );
            goto cleanup;
        }

        gitignore_match_t match;
        gitignore_eval(rules, effective_path, is_directory, &match);

        bool ignored_here = match.decided && match.ignored;
        bool by_source = false;
        if (!ignored_here) {
            by_source = source_gitignore_matches(
                source_filter, effective_path, is_directory, out
            );
            ignored_here = by_source;
        }

        if (ignored_here) {
            output_styled(
                out, OUTPUT_NORMAL, "{red}✗{reset} Profile '%s': IGNORED\n",
                profile
            );
            if (output_is_verbose(out)) {
                const char *reason = by_source
                    ? "source .gitignore"
                    : ignore_origin_describe((ignore_origin_t) match.origin);
                output_info(out, OUTPUT_NORMAL, "    Reason: %s", reason);
            }
            any_ignored = true;
        } else {
            output_success(
                out, OUTPUT_NORMAL, "Profile '%s': NOT IGNORED", profile
            );
        }
    }

    /* Summary */
    output_newline(out, OUTPUT_NORMAL);
    if (any_ignored) {
        output_info(
            out, OUTPUT_NORMAL,
            "Result: Path would be IGNORED during add/update operations"
        );
    } else {
        output_success(
            out, OUTPUT_NORMAL,
            "Result: Path would be TRACKED"
        );
    }

cleanup:
    string_array_free(profiles);
    source_filter_free(source_filter);
    ignore_rules_free(ignore_rules);
    return err;
}

/**
 * Main command implementation
 */
error_t *cmd_ignore(const dotta_ctx_t *ctx, const cmd_ignore_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(ctx->repo);
    CHECK_NULL(ctx->config);
    CHECK_NULL(opts);

    git_repository *repo = ctx->repo;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* --list-defaults is terminal: print the compiled defaults and exit.
     * Discoverability aid — lets users inspect the safety patterns
     * without grepping source or cloning the repo. */
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

    /* --test is a read-only query that walks every enabled profile by
     * itself; it doesn't use dottaignore_scope_t. Dispatch early. */
    if (has_test) {
        return test_path_ignore(
            repo, ctx->state, config, opts->test_path,
            opts->profile, ctx->arena, out
        );
    }

    /* Build the dottaignore_scope_t for edit / modify. Profile labels
     * are heap-formatted here; lifetime matches this function frame. */
    char *profile_label = NULL;
    dottaignore_scope_t scope;
    if (opts->profile) {
        profile_label = str_format("profile '%s'", opts->profile);
        if (!profile_label) {
            return ERROR(ERR_MEMORY, "Failed to format scope label");
        }
        scope = (dottaignore_scope_t){
            .branch_name = opts->profile,
            .display_label = profile_label,
            .default_seed = ignore_profile_template(),
        };
    } else {
        scope = (dottaignore_scope_t){
            .branch_name = "dotta-worktree",
            .display_label = "baseline",
            .default_seed = ignore_baseline_defaults(),
        };
    }

    /* Verify the scope branch exists once, up front, so edit/modify
     * start with a guaranteed-present branch. Error message mirrors
     * the original per-function wording. */
    bool branch_exists = false;
    error_t *err = gitops_branch_exists(repo, scope.branch_name, &branch_exists);
    if (!err && !branch_exists) {
        err = opts->profile
            ? ERROR(ERR_INVALID_ARG, "Profile '%s' does not exist", opts->profile)
            : ERROR(ERR_INTERNAL, "dotta-worktree does not exist. Run 'dotta init'.");
    }

    if (!err) {
        if (has_modify) {
            err = modify_dottaignore(
                repo, &scope, opts->add_patterns, opts->add_count,
                opts->remove_patterns, opts->remove_count, out
            );
        } else {
            err = edit_dottaignore(repo, &scope, out);
        }
    }

    free(profile_label);
    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Route the optional positional profile into `opts->profile`.
 *
 * POSITIONAL_RAW with max=1 gives us the "too many positionals" error
 * for free. When a positional is present, it wins over a preceding
 * -p/--profile flag (matches the legacy precedence — positional sets
 * profile unconditionally when present).
 */
static error_t *ignore_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_ignore_options_t *o = opts_v;

    if (o->positional_count == 1) {
        o->profile = o->positional_args[0];
    }
    return NULL;
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
    ARGS_POSITIONAL_RAW(
        cmd_ignore_options_t,positional_args, positional_count,
        0,                   1
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
        "Ignore Pattern Layers:\n"
        "  1. CLI --exclude patterns (per-operation)\n"
        "  2. Combined .dottaignore ruleset:\n"
        "     - Baseline .dottaignore (machine-local)\n"
        "     - Profile .dottaignore (synced with the profile)\n"
        "  3. Config file ignore patterns\n"
        "  4. Source .gitignore (lowest precedence)\n"
        "\n"
        "Pattern Syntax:\n"
        "  *.log                # Match all .log files\n"
        "  node_modules/        # Match directory\n"
        "  !debug.log           # Negate a prior match\n"
        "  .cache/              # Match .cache directories\n"
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
        "  %s ignore global --test ~/.bashrc         # Single profile\n",
    .opts_size   = sizeof(cmd_ignore_options_t),
    .opts        = ignore_opts,
    .post_parse  = ignore_post_parse,
    .payload     = &dotta_ext_read,
    .dispatch    = ignore_dispatch,
};
