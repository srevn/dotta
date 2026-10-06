/**
 * diff.c - Show differences between profiles and filesystem
 */

#include "cmds/diff.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/args.h"
#include "base/error.h"
#include "base/output.h"
#include "base/refspec.h"
#include "base/timeutil.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "infra/compare.h"
#include "infra/content.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "infra/pathspec.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"

/**
 * Determine if workspace item should be shown for the given direction
 *
 * Direction semantics:
 * - UPSTREAM: Show items where repository would change filesystem (undeployed
 *   files, files where Git differs from filesystem, profile reassignments that
 *   apply would acknowledge)
 * - DOWNSTREAM: Show items where filesystem would change repository (modified
 *   files, deleted files that exist in Git)
 *
 * @param item Workspace item (must not be NULL)
 * @param direction Diff direction
 * @return true if item should be shown
 */
static bool should_show_item_for_direction(
    const workspace_item_t *item,
    diff_direction_t direction
) {
    /* DIFF_BOTH is always decomposed into two explicit calls by the caller before
     * reaching this function, and post_parse resolves an unset one: a direction
     * is one of the two. */
    CHECK_ARG(
        direction == DIFF_UPSTREAM || direction == DIFF_DOWNSTREAM,
        "a diff item is shown for one direction, never both or none"
    );

    if (direction == DIFF_UPSTREAM) {
        /* Upstream: What differs that apply could act on? A comparison question,
         * not a verb route, so the bits are read directly. Show: undeployed,
         * deleted (apply would restore), content/mode/type differs, stale (Git
         * moved past what dotta last reconciled — the bytes, or a claim, which
         * rides its axis bit; apply would bring it), or profile reassignment
         * (apply acknowledges reassignment). TYPE rides along — replacing the
         * occupant is apply's (--force for the kinds the copy cannot commit),
         * and status's Conflicts remedy sends the user here to compare, so hiding
         * it answered that remedy with silence. UNVERIFIED is shown too: a look
         * that failed is a difference nobody has ruled out, and hiding it reported
         * the tree in sync over a file the user had just edited. A row beneath
         * a squatter is shown on the same ground and carries no bit to be shown
         * by: nothing there was looked at (core/workspace.h workspace_displaced_t),
         * apply writes it fresh once the squatter is replaced, and the status
         * line says so. ENCRYPTION alone stays out: how Git stores the blob is
         * no difference between Git and disk, and apply deploying it changes
         * nothing. */
        if (item->state == WORKSPACE_STATE_UNDEPLOYED ||
            item->state == WORKSPACE_STATE_DELETED) {
            return true;
        }
        if (item->state != WORKSPACE_STATE_DEPLOYED) return false;
        return item->displaced != WORKSPACE_DISPLACED_NONE ||
               (item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_STALE |
               DIVERGENCE_MODE | DIVERGENCE_OWNERSHIP | DIVERGENCE_TYPE |
               DIVERGENCE_UNVERIFIED)) ||
               workspace_reassigned(item->row, item->record, item->occupant);
    }

    /* Downstream: What would update do? The route answers verbatim
     * (workspace_item_route — the same table update's filter reads), so this
     * cannot promise a commit update refuses (STALE, CONFLICT, KIND) or hide
     * one it would take (a TYPE the copy can commit, ENCRYPTION, OWNERSHIP).
     * UNVERIFIABLE is the one refusal shown: the row's status says update skips
     * it, where a listing that left it out would say "no local changes" over a
     * file nobody could read. */
    if (item->state == WORKSPACE_STATE_DELETED) return true;
    if (item->state != WORKSPACE_STATE_DEPLOYED) return false;
    workspace_route_t route = workspace_item_route(item);
    return route == WORKSPACE_ROUTE_CAPTURE ||
           route == WORKSPACE_ROUTE_UNVERIFIABLE;
}

/**
 * Get status message from workspace item and direction
 *
 * Determines the appropriate status message based on item's state, divergence
 * flags, and diff direction.
 *
 * @param item Workspace item (must not be NULL)
 * @param direction Diff direction
 * @return Status message string
 */
static const char *get_status_message_from_item(
    const workspace_item_t *item,
    diff_direction_t direction
) {
    /* Handle state-based messages first */
    if (item->state == WORKSPACE_STATE_UNDEPLOYED) {
        return direction == DIFF_UPSTREAM
                ? "not deployed (would be created by apply)"
                : "new in repository (not deployed yet)";
    }

    if (item->state == WORKSPACE_STATE_DELETED) {
        return direction == DIFF_UPSTREAM
                ? "deleted locally (file missing)"
                : "deleted locally (would be removed by update)";
    }

    /* Beneath a squatted directory: nothing there was looked at, so no sentence
     * below is true of the path and it carries no bit for one to be read off,
     * and the way there is the claimant's — the route's two arms, said in a
     * comparison's own words. The predicate opens the line, as it does on every
     * screen that speaks of such a path (core/workspace.h workspace_displaced_t).
     * Upstream only in practice: the downstream filter admits nothing but the
     * capture route. */
    if (item->displaced == WORKSPACE_DISPLACED_TRACKED) {
        return "not looked at, beneath a squatted directory "
               "(apply --force replaces it, then writes this fresh)";
    }
    if (item->displaced == WORKSPACE_DISPLACED_DERIVED) {
        return "not looked at, beneath a squatted directory "
               "('dotta update <dir>' re-derives the way there)";
    }

    /* A look that failed: no bit below was settled, so neither verb's sentence
     * is true of the path — apply skips the row at preflight, update in its census.
     * Ranked where the route ranks it, above every settled bit, and worded by
     * whose remedy the failure is (workspace_fault_t) — the three words status
     * tags the same row with. */
    if (item->divergence & DIVERGENCE_UNVERIFIED) {
        switch (item->fault) {
            case WORKSPACE_FAULT_LOCKED:
                return direction == DIFF_UPSTREAM
                        ? "locked (apply skips it)"
                        : "locked (update skips it)";

            case WORKSPACE_FAULT_UNREADABLE:
                return direction == DIFF_UPSTREAM
                        ? "cannot be read (apply skips it)"
                        : "cannot be read (update skips it)";

            case WORKSPACE_FAULT_NONE:
            case WORKSPACE_FAULT_UNVERIFIED:
                return direction == DIFF_UPSTREAM
                        ? "could not be verified (apply skips it)"
                        : "could not be verified (update skips it)";
        }
    }

    /* Handle divergence-based messages for deployed items */
    if (item->divergence & DIVERGENCE_TYPE) {
        return direction == DIFF_UPSTREAM
                ? "type would change on apply"
                : "type changed locally";
    }

    /* Both sides moved — the route's CONFLICT: the user's bytes beside a move
     * Git made, to the bytes or to a claim. The one spelling of the fact, read
     * where apply's skip label, update's census and status's section read it.
     * Upstream only in practice: the downstream filter admits neither this nor
     * the arm below. */
    if (workspace_item_route(item) == WORKSPACE_ROUTE_CONFLICT) {
        return "changed in Git and on disk (apply --force <path> keeps Git's)";
    }

    /* Git moved past the bytes dotta last confirmed, and disk did not follow. A
     * claim Git moved alone keeps its axis sentence below: upstream, that sentence
     * is what apply does, and there are no bytes to name. */
    if (item->divergence & DIVERGENCE_STALE) return "changed in Git (would be deployed by apply)";

    if (item->divergence & DIVERGENCE_CONTENT) {
        return direction == DIFF_UPSTREAM
                ? "would be overwritten by apply"
                : "modified locally (would be committed by update)";
    }

    /* A claim alone, named by the axes it differs on in the words status tags
     * the same row with (core/workspace.h divergence_type_t) — both, where both
     * differ. */
    if ((item->divergence & DIVERGENCE_MODE) &&
        (item->divergence & DIVERGENCE_OWNERSHIP)) {
        return direction == DIFF_UPSTREAM
                ? "mode and ownership would change on apply"
                : "mode and ownership changed locally";
    }

    if (item->divergence & DIVERGENCE_MODE) {
        return direction == DIFF_UPSTREAM
                ? "mode would change on apply"
                : "mode changed locally";
    }

    if (item->divergence & DIVERGENCE_OWNERSHIP) {
        return direction == DIFF_UPSTREAM
                ? "ownership would change on apply"
                : "ownership changed locally";
    }

    /* A policy-violating blob: how Git stores the content, not a difference between
     * Git and disk. Downstream-only in practice — the upstream filter leaves
     * the lone bit out. */
    if (item->divergence & DIVERGENCE_ENCRYPTION) {
        return direction == DIFF_UPSTREAM
                ? "stored plaintext where policy asks encryption"
                : "stored plaintext (would be encrypted by update)";
    }

    /* Profile reassignment with no content/metadata divergence. Only reachable
     * via UPSTREAM (DOWNSTREAM filtered by should_show_item_for_direction). */
    if (workspace_reassigned(item->row, item->record, item->occupant)) {
        return "profile reassigned (acknowledged by apply)";
    }

    /* Every item the direction filter admits has a sentence above
     * (should_show_item_for_direction) */
    CHECK_ARG(false, "an admitted item has a status message");
}

/**
 * Show diff for a single file using workspace data
 *
 * Formats and displays the divergence the workspace analysis settled; nothing
 * is re-analyzed. The item's row is the path's view row — blob, storage path,
 * profile; non-NULL for every state the direction filter passes (untracked and
 * orphaned items were filtered there).
 *
 * @param item Workspace item with divergence info (must not be NULL)
 * @param cache Content cache (must not be NULL)
 * @param direction Diff direction
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t show_file_diff_from_workspace(
    const workspace_item_t *item,
    content_cache_t *cache,
    diff_direction_t direction,
    const cmd_diff_options_t *opts,
    output_t *out
) {
    CHECK_NULL(item);
    CHECK_NULL(cache);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    const manifest_row_t *file = item->row;

    /* Name-only output */
    if (opts->name_only) {
        output_print(out, OUTPUT_NORMAL, "%s\n", item->filesystem_path);
        return NULL;
    }

    /* Show file header */
    output_print(
        out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
        file->profile
    );
    output_print(
        out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s\n",
        file->storage_path
    );

    /* Get status message from workspace item (no re-analysis needed) */
    const char *status_msg = get_status_message_from_item(item, direction);

    /* Determine status color */
    output_color_t status_color = OUTPUT_COLOR_YELLOW;
    if (item->state == WORKSPACE_STATE_DELETED ||
        item->state == WORKSPACE_STATE_UNDEPLOYED) {
        status_color = OUTPUT_COLOR_RED;
    } else if (item->displaced != WORKSPACE_DISPLACED_NONE) {
        status_color = OUTPUT_COLOR_YELLOW;  /* nothing here was looked at */
    } else if (item->divergence & DIVERGENCE_UNVERIFIED) {
        status_color = OUTPUT_COLOR_MAGENTA; /* status's colour for the failed look */
    } else if (item->divergence & DIVERGENCE_TYPE) {
        status_color = OUTPUT_COLOR_RED;
    } else if (workspace_reassigned(item->row, item->record, item->occupant) &&
        (item->divergence & ~DIVERGENCE_ENCRYPTION) == DIVERGENCE_NONE) {
        /* A pure reassignment. The blob bit, ENCRYPTION, does not demote it: it
         * is about how Git stores the blob, not a difference between Git and
         * disk. */
        status_color = OUTPUT_COLOR_CYAN;
    }

    /* Show status */
    output_print(out, OUTPUT_NORMAL, "{dim}# Status:{reset}  ");
    output_colored(out, OUTPUT_NORMAL, status_color, "%s\n", status_msg);

    /* For missing files, type changes and failed looks, no content diff to show:
     * an unverified row has no bytes the analysis could compare, and reading
     * them here would fail the way the look did. */
    if (item->state == WORKSPACE_STATE_DELETED ||
        item->state == WORKSPACE_STATE_UNDEPLOYED ||
        (item->divergence & (DIVERGENCE_TYPE | DIVERGENCE_UNVERIFIED))) {
        return NULL;
    }

    /* Beneath a squatter: there are no bytes of this path's to compare — Git's
     * blob against the squatter's target's file would be a diff of two unrelated
     * things, and nothing here is overwritten (apply --force replaces the squatter
     * and writes the row fresh). */
    if (item->displaced != WORKSPACE_DISPLACED_NONE) return NULL;

    /* Only a content difference has bytes to render: the copy's own edit, or
     * the blob Git moved past, which disk still holds. A claim, whoever moved
     * it (CLAIM_MOVED is no byte), a reassignment and how Git stores the blob
     * differ in nothing a hunk could show, and a sealed blob is opened for none
     * of them. */
    if (!(item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_STALE))) return NULL;

    /* Get content from cache via the row's blob_oid (borrowed reference - don't
     * free), read as the entry the row's type says it is */
    git_filemode_t mode = gitops_type_filemode(file->type);
    const buffer_t *content = NULL;
    error_t err = content_cache_get_from_blob_oid(
        cache, &file->blob_oid, mode, file->storage_path, file->profile, &content
    );
    if (err) return err;

    /* Generate diff */
    compare_direction_t cmp_dir = (direction == DIFF_UPSTREAM)
                                ? CMP_DIR_UPSTREAM : CMP_DIR_DOWNSTREAM;

    file_diff_t diff = { 0 };
    err = compare_generate_diff(
        content, item->filesystem_path, file->storage_path, mode, cmp_dir, &diff
    );
    if (err) return err;

    /* The separator belongs to a text, not to a verdict: where the renderer's
     * own look found the copy matching after all — the one thing that can change
     * between the load and here — the status line above stands alone. */
    if (diff.diff_text) {
        output_print(out, OUTPUT_NORMAL, "{dim}---{reset}\n");
        output_print_diff(out, OUTPUT_NORMAL, diff.diff_text);
    }

    compare_diff_deinit(&diff);

    return NULL;
}

/**
 * Present diffs for a specific direction using workspace analysis
 *
 * Filters pre-analyzed divergence and generates diffs for display. Uses cached
 * metadata and content from workspace/caches.
 *
 * @param diverged Diverged items from workspace (borrowed slice)
 * @param cache Content cache for blob access (must not be NULL)
 * @param direction Diff direction (UPSTREAM or DOWNSTREAM)
 * @param scope Operation scope (profile + path dimensions; diff has no excludes)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 * @param diff_count Output: number of diffs shown (must not be NULL)
 * @param unverified Output: how many of them were rows the analysis could not
 *                   look at; shown by their status line, no hunk (must not be NULL)
 * @return Error or NULL on success
 */
static error_t present_diffs_for_direction(
    workspace_items_t diverged,
    content_cache_t *cache,
    diff_direction_t direction,
    const scope_t *scope,
    const cmd_diff_options_t *opts,
    output_t *out,
    size_t *diff_count,
    size_t *unverified
) {
    CHECK_NULL(cache);
    CHECK_NULL(scope);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);
    CHECK_NULL(unverified);

    *diff_count = 0;
    *unverified = 0;

    error_t err = NULL;

    /* Early return if no diverged items */
    if (diverged.count == 0) return NULL;

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* Filter 1: Only process FILES (skip directories) */
        if (item->item_kind != PATH_KIND_FILE) continue;

        /* Filter 2: Check file filter (user-specified files) */
        if (!scope_accepts_path(
            scope, item->filesystem_path, item->storage_path, PATH_KIND_FILE
            )) {
            continue;
        }

        /* Filter 3: Direction-based filtering */
        if (!should_show_item_for_direction(item, direction)) continue;

        /* Filter 4: Profile filter (CLI filtering) */
        if (!scope_accepts_profile(scope, item->profile)) continue;

        /* Each entry is a block; a name-only listing has none */
        if (!opts->name_only) {
            output_gap(out, OUTPUT_NORMAL);
        }

        /* Show the diff (content already analyzed by workspace) */
        err = show_file_diff_from_workspace(item, cache, direction, opts, out);
        if (err) return err;

        (*diff_count)++;

        if (item->divergence & DIVERGENCE_UNVERIFIED) {
            (*unverified)++;
        }
    }

    return NULL;
}

/**
 * Print commit header with metadata
 */
static void print_commit_header(
    output_t *out,
    const git_commit *commit,
    const char *profile
) {
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(commit));

    const git_signature *author = git_commit_author(commit);
    time_t commit_time = (time_t) author->when.time;

    /* Format absolute time */
    struct tm tm_info;
    localtime_r(&commit_time, &tm_info);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%a %b %d %H:%M:%S %Y", &tm_info);

    /* Format relative time */
    char relative_buf[64];
    timeutil_relative(commit_time, relative_buf, sizeof(relative_buf));

    /* Print header with colors */
    output_print(
        out, OUTPUT_NORMAL, "{yellow}commit %s{reset}",
        oid_str
    );
    if (profile) {
        output_print(
            out, OUTPUT_NORMAL, " {cyan}(%s){reset}",
            profile
        );
    }
    output_endline(out, OUTPUT_NORMAL);

    output_print(
        out, OUTPUT_NORMAL, "{bold}Author:{reset} %s <%s>\n",
        author->name, author->email
    );
    output_print(
        out, OUTPUT_NORMAL, "{bold}Date:{reset}   %s (%s)\n",
        time_buf, relative_buf
    );
    output_gap(out, OUTPUT_NORMAL);

    /* Commit message (indented). A line and its newline are one step; the last
     * line needs no newline, so a blank line inside a message survives. */
    const char *line = git_commit_message(commit);
    while (*line) {
        size_t len = strcspn(line, "\n");
        output_print(out, OUTPUT_NORMAL, "    %.*s\n", (int) len, line);
        line += len + (line[len] == '\n');
    }

    output_gap(out, OUTPUT_NORMAL);
}

/**
 * Print diff statistics
 */
static error_t print_diff_stats(output_t *out, git_diff *diff) {
    CHECK_NULL(out);
    CHECK_NULL(diff);

    git_diff_stats *stats = NULL;
    error_t err = gitops_diff_get_stats(diff, &stats);
    if (err) return err;

    size_t files_changed = git_diff_stats_files_changed(stats);
    size_t insertions = git_diff_stats_insertions(stats);
    size_t deletions = git_diff_stats_deletions(stats);

    /* Print stats with color */
    output_print(
        out, OUTPUT_NORMAL, " %zu file%s changed",
        files_changed, files_changed == 1 ? "" : "s"
    );

    if (insertions > 0) {
        output_print(
            out, OUTPUT_NORMAL, ", {green}%zu insertion%s(+){reset}",
            insertions, insertions == 1 ? "" : "s"
        );
    }

    if (deletions > 0) {
        output_print(
            out, OUTPUT_NORMAL, ", {red}%zu deletion%s(-){reset}",
            deletions, deletions == 1 ? "" : "s"
        );
    }

    output_endline(out, OUTPUT_NORMAL);

    git_diff_stats_free(stats);

    return NULL;
}

/**
 * Print one line of a patch (git_diff_print's GIT_DIFF_FORMAT_PATCH)
 */
static int print_diff_line_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    output_t *out = (output_t *) payload;
    (void) delta;
    (void) hunk;

    output_color_t line_color = OUTPUT_COLOR_RESET;

    switch (line->origin) {
        case GIT_DIFF_LINE_ADDITION:
            line_color = OUTPUT_COLOR_GREEN;
            break;
        case GIT_DIFF_LINE_DELETION:
            line_color = OUTPUT_COLOR_RED;
            break;
        case GIT_DIFF_LINE_FILE_HDR:
        case GIT_DIFF_LINE_HUNK_HDR:
            line_color = OUTPUT_COLOR_CYAN;
            break;
        default:
            break;
    }

    /* A patch line is a payload, its bytes the file's own and libgit2's quoted
     * headers, written as they are: a change line's origin first, each in the
     * line's colour */
    if (line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION ||
        line->origin == GIT_DIFF_LINE_CONTEXT) {
        output_write(out, OUTPUT_NORMAL, line_color, &line->origin, 1);
    }
    output_write(out, OUTPUT_NORMAL, line_color, line->content, line->content_len);

    /* Add newline if not present */
    if (line->content_len == 0 || line->content[line->content_len - 1] != '\n') {
        output_endline(out, OUTPUT_NORMAL);
    }

    return 0;
}

/**
 * Compare a commit's view against the current filesystem
 *
 * The commit-to-workspace comparison: every file row of the view
 * manifest_build_profile computed from the profile at the commit, compared against
 * what stands at its path now. A directory row — a claim of the tree's own
 * metadata.json — has no content to diff and is passed over by its type, the
 * test core/manifest.h leaves to a reader that wants files. Each row carries
 * the profile whose claim it is, the commit's, and its blob opens under the row's
 * own binding.
 *
 * @param view The commit's view (must not be NULL; its rows are the command arena's
 *             and live until command end)
 * @param file_filter File filter for CLI (can be NULL for no filter)
 * @param opts Command options (must not be NULL)
 * @param cache Shared content cache (the run's, must not be NULL)
 * @param out Output context (must not be NULL)
 * @param diff_count Output: number of diffs shown (must not be NULL)
 * @return Error or NULL on success
 */
static error_t compare_tree_files_to_filesystem(
    const manifest_t *view,
    const pathspec_t *file_filter,
    const cmd_diff_options_t *opts,
    content_cache_t *cache,
    output_t *out,
    size_t *diff_count
) {
    CHECK_NULL(view);
    CHECK_NULL(opts);
    CHECK_NULL(cache);
    CHECK_NULL(out);
    CHECK_NULL(diff_count);

    *diff_count = 0;

    manifest_rows_t rows = manifest_rows(view);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *entry = rows.entries[i];
        const char *filesystem_path = entry->filesystem_path;
        const char *storage_path = entry->storage_path;
        const char *profile = entry->profile;

        /* A directory row: no content to diff */
        if (entry->type == PATH_TYPE_DIRECTORY) continue;

        /* Check file filter */
        if (!pathspec_matches(file_filter, filesystem_path, storage_path, PATH_KIND_FILE)) {
            continue;
        }

        git_filemode_t mode = gitops_type_filemode(entry->type);

        /* Name-only output */
        if (opts->name_only) {
            /* One look, handed to the comparison below rather than left for it
             * to take one of its own: the lstat names the path itself (a broken
             * symlink is present — only its target is absent), and a path nothing
             * stands at is named before a blob is loaded, there being nothing
             * to compare against. So this form asks its question through the
             * window the full form already has — the renderer's own look, then
             * its read — where it used to look twice and could see two different
             * worlds. */
            struct stat st;
            if (fs_lstat(filesystem_path, &st) != 0) {
                output_print(out, OUTPUT_NORMAL, "%s\n", filesystem_path);
                (*diff_count)++;
                continue;
            }

            /* Get content from historical commit (cached) */
            const buffer_t *hist_content = NULL;
            error_t err = content_cache_get_from_blob_oid(
                cache, &entry->blob_oid, mode, storage_path, profile, &hist_content
            );
            if (err) return err;

            /* Compare with filesystem */
            compare_result_t result;
            err = compare_buffer_to_disk(
                hist_content, filesystem_path, mode, &st, &result
            );
            if (err) return err;

            if (result != CMP_EQUAL) {
                output_print(out, OUTPUT_NORMAL, "%s\n", filesystem_path);
                (*diff_count)++;
            }
            continue;
        }

        /* Full diff output: the renderer takes the one look, and the verdict is
         * read off its result — so the bytes judged are the bytes rendered, where
         * this loop used to compare the row itself and then hand the renderer
         * the same question four lines later. */
        const buffer_t *hist_content = NULL;
        error_t err = content_cache_get_from_blob_oid(
            cache, &entry->blob_oid, mode, storage_path, profile, &hist_content
        );
        if (err) return err;

        file_diff_t diff = { 0 };
        err = compare_generate_diff(
            hist_content, filesystem_path, storage_path, mode, CMP_DIR_DOWNSTREAM, &diff
        );
        if (err) return err;

        /* The status message, in the commit's words rather than the renderer's
         * — and the verdict this form has no line for is a copy that is the
         * commit's, which prints nothing at all. The renderer's own text for
         * the two verdicts with no bytes to show is generated and dropped here:
         * it is the workspace arm's fallback, not this loop's vocabulary. */
        const char *status_msg = NULL;
        output_color_t status_color = OUTPUT_COLOR_RED;

        switch (diff.status) {
            case CMP_EQUAL:
                break;
            case CMP_MISSING:
                status_msg = "deleted locally (file missing)";
                break;
            case CMP_TYPE_DIFF:
                status_msg = "type changed locally";
                break;
            case CMP_DIFFERENT:
                status_msg = "modified locally since commit";
                status_color = OUTPUT_COLOR_YELLOW;
                break;
        }

        if (status_msg) {
            output_gap(out, OUTPUT_NORMAL);

            /* Show file header */
            output_print(
                out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
                profile
            );
            output_print(
                out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s\n",
                storage_path
            );

            output_print(out, OUTPUT_NORMAL, "{dim}# Status:{reset}  ");
            output_colored(out, OUTPUT_NORMAL, status_color, "%s\n", status_msg);

            /* Only a content difference has bytes to render */
            if (diff.status == CMP_DIFFERENT) {
                output_print(out, OUTPUT_NORMAL, "{dim}---{reset}\n");
                output_print_diff(out, OUTPUT_NORMAL, diff.diff_text);
            }

            (*diff_count)++;
        }

        compare_diff_deinit(&diff);
    }

    return NULL;
}

/**
 * Validate file filter entries against a view
 *
 * Asks each filter entry alone — an exact path by equality or ancestry, a pattern
 * by whether it matches at any rung, either polarity — against the view's rows,
 * each by both its names (the entry reads the one in its own vocabulary) and by
 * its own kind, read off its type. An entry that reaches a file row has content
 * to diff and is not answered. One that reaches only directory rows is answered
 * for what it is: a path with no content to diff — a tracked directory or a derived
 * one alike, since neither kind has any (core/manifest.h). One that reaches nothing
 * — which likely indicates a typo — is warned in the words of what the view's
 * paths are: the enabled view's are active paths, a commit's are the commit's,
 * and a miss in one says nothing of the other. The list hint follows the warnings
 * as their remedy.
 *
 * Per-entry attribution matters here: the combined program folds one pattern's
 * negation into another's verdict and would under-count coverage on overlap;
 * and a negation that excluded something has done its work, so it is not called
 * "matches nothing" (pathspec_entry_matches_at).
 *
 * One implementation serves both arms that compare against a view: the commit
 * arm's is the one manifest_build_profile computes from the profile at the commit,
 * the workspace arm's the one the dispatcher built and the workspace joins.
 * Coverage is a question about the view alone — nothing here takes a look — so
 * each arm asks it before anything is compared: an entry is answered beside a
 * diff as well as in place of one, and the answer is the same under --name-only.
 *
 * @param file_filter File filter to validate (NULL = no filter, nothing to answer)
 * @param view The view the arm compares against (must not be NULL)
 * @param what What the view's paths are on the screen: "active path" for the
 *             enabled view, "path of the commit" for one commit's (must not be
 *             NULL)
 * @param out Output context for the answers
 * @return false where no entry reaches a file row — nothing under the filter
 *         can diff, and the answers are the whole report; true otherwise, and
 *         always under no filter
 */
static bool validate_filter_paths(
    const pathspec_t *file_filter,
    const manifest_t *view,
    const char *what,
    output_t *out
) {
    if (!file_filter) return true;

    manifest_rows_t rows = manifest_rows(view);
    size_t covered = 0;     /* Entries reaching a file row */
    size_t unmatched = 0;   /* Entries reaching nothing, each warned */

    for (size_t e = 0; e < pathspec_count(file_filter); e++) {
        /* The row the entry reaches: a file row ends the search, content being
         * what a diff shows, and a directory row stands until one does */
        const manifest_row_t *reached = NULL;
        for (size_t i = 0; i < rows.count; i++) {
            const manifest_row_t *row = rows.entries[i];
            if (!pathspec_entry_matches_at(
                file_filter, e,
                row->filesystem_path,
                row->storage_path,
                path_type_kind(row->type)
                )) {
                continue;
            }
            reached = row;
            if (row->type != PATH_TYPE_DIRECTORY) break;
        }

        /* Content to diff, and nothing to say */
        if (reached && reached->type != PATH_TYPE_DIRECTORY) {
            covered++;
            continue;
        }

        /* A directory row alone has nothing to diff; no row at all is warned */
        pathspec_entry_t entry = pathspec_entry_at(file_filter, e);
        if (reached && entry.glob) {
            output_info(
                out, OUTPUT_NORMAL,
                "Pattern '%s' matches only directories (no content to diff)",
                entry.text
            );
        } else if (reached) {
            output_info(
                out, OUTPUT_NORMAL,
                "'%s' matches only directories (no content to diff)",
                entry.text
            );
        } else if (entry.glob) {
            output_warning(
                out, OUTPUT_NORMAL,
                "No %s matches pattern '%s'",
                what, entry.text
            );
            unmatched++;
        } else {
            output_warning(
                out, OUTPUT_NORMAL,
                "No %s matches '%s'",
                what, entry.text
            );
            unmatched++;
        }
    }

    /* The warnings' one remedy, said once under them all */
    if (unmatched > 0) {
        output_hint(
            out, OUTPUT_NORMAL,
            "Use 'dotta list <profile>' to see managed files"
        );
    }

    return covered > 0;
}

/**
 * Diff commit to workspace - Compare historical commit with filesystem
 *
 * CURRENT LIMITATION: Single-profile comparison only. When multiple profiles
 * are enabled, this function compares only the profile that contains the specified
 * commit (the first holder, from the highest precedence down)
 *
 * The commit is looked for in the enabled set, narrowed to the profiles -p names
 * where it names any (core/scope.h scope_resolve_commit): -p is how a spelling
 * every profile holds — HEAD, HEAD~N — names the profile it means, as `show -p`
 * names it, and a commit of a profile -p left out is not found. The path filter
 * is derived from scope_paths (raw CLI positional args, never narrowed).
 *
 * @param ctx Dispatch context (must not be NULL; reads the repository, this
 *            machine's mount table, and the borrowed command arena that backs
 *            the commit's view)
 * @param commit_ref Commit reference to compare (must not be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_commit_to_workspace(
    const dotta_ctx_t *ctx,
    const char *commit_ref,
    const scope_t *scope,
    const cmd_diff_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(commit_ref);
    CHECK_NULL(scope);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const mount_table_t *mounts = ctx->run.mounts;
    content_cache_t *cache = ctx->run.content_cache;
    arena_t *arena = ctx->arena;
    output_t *out = ctx->out;

    /* The profiles the commit is looked for in: the enabled set, narrowed to
     * the ones -p names where it names any (the scope's face is exactly that
     * set). */
    const string_array_t *searched = scope_profiles(scope);
    const string_array_t *filter = scope_filters_profiles(scope) ? searched : NULL;
    const pathspec_t *file_filter = scope_paths(scope);

    error_t err = NULL;
    git_commit *commit = NULL;
    const char *name = NULL;  /* borrowed from the enabled set */
    git_tree *tree = NULL;

    /* Step 1: Resolve commit to find which profile contains it. The search answers
     * for every profile ahead of the holder, so a profile that will not read
     * cancels the diff rather than let a later one answer in its place
     * (core/scope.h scope_resolve_commit). */
    err = scope_resolve_commit(
        repo, scope_enabled(scope), filter, commit_ref, &commit, &name
    );
    if (err) goto cleanup;

    /* Step 2: Print commit header */
    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(commit));

    /* Warn when more than one profile was searched: only the profile containing
     * the commit is compared against the filesystem. */
    if (searched->count > 1) {
        output_info(
            out, OUTPUT_NORMAL, "Note: comparing commit against profile '%s' only "
            "(commit-to-workspace compares one profile at a time)", name
        );
        output_gap(out, OUTPUT_NORMAL);
    }

    output_print(
        out, OUTPUT_NORMAL, "{bold}diff --dotta %s..workspace{reset}\n",
        oid_str
    );
    output_gap(out, OUTPUT_NORMAL);

    print_commit_header(out, commit, name);

    /* Step 3: Get tree from THE HISTORICAL COMMIT (not HEAD!) — from the commit
     * in hand, the OID helper beside it being a second lookup of what is here. */
    int rc = git_commit_tree(&tree, commit);
    if (rc < 0) {
        err = error_git(rc, "Failed to get tree from commit %s", oid_str);
        goto cleanup;
    }

    /* Step 4: Build the historical view: the profile at the commit's tree, built
     * into a view and let go.
     *
     * The tree's own claim sheet is the profile's to read (core/profiles.h), so
     * the historical rows carry the modes and stamps that commit claimed, and a
     * sheet that will not load refuses the diff instead of showing Git's defaults
     * as though nothing had been claimed.
     *
     * The view is allocated into the borrowed command arena; it outlives every
     * reader below, then lives until command end. */
    manifest_t *historical = NULL;
    profile_t *profile = profile_open(name, tree);
    err = manifest_build_profile(profile, mounts, arena, &historical);
    profile_free(profile);
    if (err) goto cleanup;

    /* Step 5: The filter's coverage over the commit's view, answered before
     * anything is compared, as the workspace arm answers it over its own. Where
     * no entry reaches content, nothing can diff, and the answers are the whole
     * report. */
    if (!validate_filter_paths(file_filter, historical, "path of the commit", out)) {
        goto cleanup;
    }

    /* Step 6: Compare the commit's view against the current filesystem */
    size_t diff_count = 0;
    err = compare_tree_files_to_filesystem(
        historical, file_filter, opts, cache, out, &diff_count
    );
    if (err) goto cleanup;

    /* Under a filter the comparison passed over every row outside it, so an empty
     * one claims the scope, in the workspace arm's words; else the whole */
    if (diff_count == 0 && !opts->name_only) {
        if (file_filter) {
            output_info(out, OUTPUT_NORMAL, "No differences in scope");
        } else {
            output_info(
                out, OUTPUT_NORMAL, "No differences between commit and workspace"
            );
        }
    }

cleanup:
    git_tree_free(tree);
    git_commit_free(commit);

    return err;
}

/**
 * The selection of a commit range: what select_delta reads and what it leaves
 *
 * The filter, and what a delta's path is resolved through — the profile the range
 * belongs to and this machine's table, under which a past tree's names are placed
 * where the binding stands now, as the commit-to-workspace arm places them
 * (manifest_build_profile).
 */
typedef struct {
    const pathspec_t *filter;       /* never NULL: the callback is installed under a filter alone */
    const mount_table_t *mounts;
    const char *profile;
    arena_t *arena;                 /* the paths' lifetime: the command's */
} delta_select_t;

/**
 * Select one delta of a commit range under the path filter
 *
 * libgit2's notify callback, called for every delta before it is inserted into
 * the diff (an unmodified pair never reaches it): 0 keeps the delta, a positive
 * return drops it. The one matcher every other filter site reads decides here
 * too, by both of the delta's names — its storage path, and the filesystem path
 * the profile's binding gives it, NULL for a claim this machine cannot place,
 * which a storage-shaped entry alone then selects — so a commit range and the
 * workspace read one filter alike: a filesystem filter selects the deltas standing
 * beneath it whatever label they carry, a pattern is anchored where gitignore
 * anchors it, and `*` stops at a slash. Handing libgit2 the entries as its own
 * pathspec read them by fnmatch instead, where `home/<star>.lua` reached
 * `home/dir/b.lua`.
 *
 * Installed only when a filter was given: the diff under none holds every delta,
 * the repository's own files included, and prints as it always has. Under a filter
 * those files are out — the sheet has no row for a filter to name — and every
 * selected delta is a managed path.
 *
 * One path per delta: a tree-to-tree diff finds no renames, and libgit2 spells
 * both sides of every delta from one string, so the new side names the old as well.
 *
 * @param diff     The diff so far (unread)
 * @param delta    The delta about to be inserted
 * @param matched  libgit2's own pathspec match (none is set; unread)
 * @param payload  The selection (delta_select_t)
 * @return 0 to keep the delta, 1 to drop it
 */
static int select_delta(
    const git_diff *diff, const git_diff_delta *delta, const char *matched,
    void *payload
) {
    (void) diff;
    (void) matched;

    delta_select_t *sel = payload;
    const char *path = delta->new_file.path;

    if (!label_prefixes(path)) return 1;

    const char *filesystem_path = mount_resolve(sel->arena, sel->mounts, sel->profile, path);

    return pathspec_matches(
        sel->filter, filesystem_path, path, PATH_KIND_FILE
    ) ? 0 : 1;
}

/**
 * Diff two commits
 *
 * The two commits are one search's (core/scope.h scope_resolve_range): the first
 * profile holding both, in the enabled set narrowed to the profiles -p names
 * where it names any, as the workspace arm looks for its one. The path filter
 * is derived from scope_paths (raw CLI positional args, never narrowed) and applied
 * delta by delta as the diff is generated (select_delta, each delta by both its
 * names under this machine's table), so the diff printed — names, stats, patch
 * — is the selection and nothing else.
 *
 * @param ctx Dispatch context (must not be NULL; reads the repository, this
 *            machine's mount table, the command arena and the output)
 * @param commit1_ref The first commit named (must not be NULL)
 * @param commit2_ref The second commit named, whose header is printed (must not
 *                    be NULL)
 * @param scope Operation scope (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_commits(
    const dotta_ctx_t *ctx,
    const char *commit1_ref,
    const char *commit2_ref,
    const scope_t *scope,
    const cmd_diff_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(commit1_ref);
    CHECK_NULL(commit2_ref);
    CHECK_NULL(scope);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const mount_table_t *mounts = ctx->run.mounts;
    arena_t *arena = ctx->arena;
    output_t *out = ctx->out;

    /* The profiles -p names, or NULL: every enabled one */
    const string_array_t *filter = scope_filters_profiles(scope)
        ? scope_profiles(scope) : NULL;
    const pathspec_t *file_filter = scope_paths(scope);

    error_t err = NULL;
    git_commit *commit1 = NULL;
    git_commit *commit2 = NULL;
    const char *profile = NULL;  /* borrowed from the enabled set, which outlives this call */
    git_tree *tree1 = NULL;
    git_tree *tree2 = NULL;
    git_diff *diff = NULL;

    /* Both ends in one search: the first profile whose history holds both, each
     * profile's head read once for the two (core/scope.h scope_resolve_range).
     * A profile that will not read cancels the range rather than let a later
     * one answer for it, and ends held only by different profiles are no range. */
    err = scope_resolve_range(
        repo, scope_enabled(scope), filter, commit1_ref, commit2_ref, &commit1,
        &commit2, &profile
    );
    if (err) goto cleanup;

    /* Print diff range header */
    char oid1_str[8], oid2_str[8];
    git_oid_tostr(oid1_str, sizeof(oid1_str), git_commit_id(commit1));
    git_oid_tostr(oid2_str, sizeof(oid2_str), git_commit_id(commit2));

    output_print(
        out, OUTPUT_NORMAL, "{bold}diff --dotta %s..%s{reset}\n",
        oid1_str, oid2_str
    );
    output_gap(out, OUTPUT_NORMAL);

    /* Print second commit header (the "new" one) */
    print_commit_header(out, commit2, profile);

    /* Get trees from the two commits in hand — the OID helper beside this one
     * would look each of them up a second time (the workspace arm above reads
     * its tree the same way). */
    int rc = git_commit_tree(&tree1, commit1);
    if (rc < 0) {
        err = error_git(rc, "Failed to get tree from commit %s", oid1_str);
        goto cleanup;
    }

    rc = git_commit_tree(&tree2, commit2);
    if (rc < 0) {
        err = error_git(rc, "Failed to get tree from commit %s", oid2_str);
        goto cleanup;
    }

    /* Generate the diff, the filter selecting each delta on its way in. The
     * selection is borrowed for the call: libgit2 reads the payload only while
     * generating. */
    delta_select_t selection = {
        .filter = file_filter, .mounts = mounts, .profile = profile,
        .arena  = arena
    };
    git_diff_options diff_opts;
    git_diff_options_init(&diff_opts, GIT_DIFF_OPTIONS_VERSION);
    if (file_filter) {
        diff_opts.notify_cb = select_delta;
        diff_opts.payload = &selection;
    }

    err = gitops_diff_trees(repo, tree1, tree2, &diff_opts, &diff);
    if (err) goto cleanup;

    if (opts->name_only) {
        /* Name-only: each changed path, cyan, as the patch's file header colours
         * it — written here as the datum it is, never libgit2's name-only line,
         * which is the path raw where git quotes it (lib/libgit2/src/libgit2/
         * diff_print.c diff_print_one_name_only). Every delta is a change: a
         * tree-to-tree diff drops an unmodified one unless INCLUDE_UNMODIFIED
         * is asked (diff_generate.c diff_delta__from_two), and dotta never asks
         * it. */
        size_t count = git_diff_num_deltas(diff);
        for (size_t i = 0; i < count; i++) {
            const git_diff_delta *delta = git_diff_get_delta(diff, i);
            output_colored(
                out, OUTPUT_NORMAL, OUTPUT_COLOR_CYAN, "%s\n",
                delta->new_file.path
            );
        }
    } else {
        /* Full diff: statistics followed by patch */
        err = print_diff_stats(out, diff);
        if (err) goto cleanup;

        output_gap(out, OUTPUT_NORMAL);

        rc = git_diff_print(diff, GIT_DIFF_FORMAT_PATCH, print_diff_line_cb, out);
        if (rc < 0) {
            err = error_git(rc, "Cannot print the diff");
            goto cleanup;
        }
    }

cleanup:
    if (diff) git_diff_free(diff);
    if (tree2) git_tree_free(tree2);
    if (tree1) git_tree_free(tree1);
    if (commit2) git_commit_free(commit2);
    if (commit1) git_commit_free(commit1);

    return err;
}

/**
 * Workspace diff - Compare current profiles with filesystem using workspace module
 *
 * The filter's coverage is answered over the view first, and a filter under which
 * nothing can diff ends the diff at its answers, no workspace loaded
 * (validate_filter_paths). Otherwise the workspace is loaded over the same view,
 * its learning flushed, and the diverged items presented per direction under
 * the scope — the analysis settled every verdict, and nothing here re-reads one.
 *
 * @param ctx Dispatch context (must not be NULL; reads the repository, the borrowed
 *            state handle, the shared blob-content cache, and the view over the
 *            enabled set)
 * @param scope Operation scope — profile and path filters (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_workspace(
    const dotta_ctx_t *ctx,
    const scope_t *scope,
    const cmd_diff_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(scope);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;  /* Borrowed from dispatcher; do not free */
    content_cache_t *cache = ctx->run.content_cache;
    const manifest_t *manifest = ctx->run.manifest;
    const config_t *config = ctx->config;
    arena_t *arena = ctx->arena;
    output_t *out = ctx->out;

    /* Step 1: The filter's coverage over the view — the one the workspace joins,
     * and all the question needs. Where no entry reaches content, nothing can
     * diff, the answers are the whole report, and no workspace is loaded. */
    if (!validate_filter_paths(scope_paths(scope), manifest, "active path", out)) return NULL;

    /* Step 2: Load the workspace. Orphans have no reader here, and the untracked
     * scan is update's. */
    workspace_options_t ws_opts = {
        .analyze_orphans   = false,
        .analyze_untracked = false
    };

    workspace_t *ws = NULL;
    error_t err = workspace_load(
        repo, state, config, cache, manifest, &ws_opts, arena, &ws
    );
    if (err) return err;

    /* What the load owes the record — its observations, its confirmations, the
     * voids of orders the view took back (core/workspace.h workspace_flush) —
     * the confirmations seeding the fast path for subsequent status/apply calls.
     * The flush keeps the failure of the transaction it takes, so diff renders
     * what the load read whatever the flush met. */
    err = workspace_flush(ws);
    if (err) return err;

    /* Step 3: Get pre-analyzed divergence from workspace */
    workspace_items_t diverged = workspace_diverged(ws);

    /* Step 4: Filter and present diffs based on direction. A row the analysis
     * could not look at is shown by its status line and counted: it is never
     * "in sync", and each section says how many it could not settle. */
    size_t total_diff_count = 0;

    if (opts->direction == DIFF_BOTH) {
        /* Show both directions with headers */
        size_t upstream_count = 0, downstream_count = 0;
        size_t unverified = 0;

        /* Upstream section */
        output_section(out, OUTPUT_NORMAL, "Upstream (repository → filesystem)");
        output_info(out, OUTPUT_NORMAL, "Shows what 'dotta apply' would change");
        output_gap(out, OUTPUT_NORMAL);

        err = present_diffs_for_direction(
            diverged, cache, DIFF_UPSTREAM, scope, opts, out,
            &upstream_count, &unverified
        );
        if (err) return err;

        if (upstream_count == 0 && !opts->name_only) {
            output_info(out, OUTPUT_NORMAL, "No upstream differences");
        }
        if (unverified > 0 && !opts->name_only) {
            output_info(
                out, OUTPUT_NORMAL, "%zu file%s could not be verified",
                unverified, unverified == 1 ? "" : "s"
            );
        }

        /* Downstream section */
        output_section(out, OUTPUT_NORMAL, "Downstream (filesystem → repository)");
        output_info(out, OUTPUT_NORMAL, "Shows what 'dotta update' would commit");
        output_gap(out, OUTPUT_NORMAL);

        err = present_diffs_for_direction(
            diverged, cache, DIFF_DOWNSTREAM, scope, opts, out,
            &downstream_count, &unverified
        );
        if (err) return err;

        if (downstream_count == 0 && !opts->name_only) {
            output_info(out, OUTPUT_NORMAL, "No downstream differences");
        }
        if (unverified > 0 && !opts->name_only) {
            output_info(
                out, OUTPUT_NORMAL, "%zu file%s could not be verified",
                unverified, unverified == 1 ? "" : "s"
            );
        }

        total_diff_count = upstream_count + downstream_count;
    } else {
        size_t unverified = 0;
        err = present_diffs_for_direction(
            diverged, cache, opts->direction, scope, opts, out,
            &total_diff_count, &unverified
        );
        if (err) return err;

        /* An empty screen says what the verb it previews says of its own empty
         * run. Upstream, apply's: under a filter the scope the screen showed
         * and nothing past it — every path was loaded and analyzed, only those
         * in scope presented — else the repository (cmd_apply). Downstream,
         * update's, which names no whole to qualify. */
        if (total_diff_count == 0 && !opts->name_only) {
            if (opts->direction == DIFF_UPSTREAM) {
                if (scope_filters_profiles(scope) || scope_filters_paths(scope)) {
                    output_info(out, OUTPUT_NORMAL, "No differences in scope");
                } else {
                    output_info(
                        out, OUTPUT_NORMAL,
                        "No differences (repository and filesystem in sync)"
                    );
                }
            } else {
                output_info(out, OUTPUT_NORMAL, "No local changes to commit");
            }
        }
        if (unverified > 0 && !opts->name_only) {
            output_info(
                out, OUTPUT_NORMAL, "%zu file%s could not be verified",
                unverified, unverified == 1 ? "" : "s"
            );
        }
    }

    return NULL;
}

/**
 * Diff command implementation
 */
error_t cmd_diff(const dotta_ctx_t *ctx, const cmd_diff_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const manifest_t *manifest = ctx->run.manifest; /* The view at dispatch */
    output_t *out = ctx->out;

    scope_t *scope = NULL;

    /* Build operation scope
     *
     *   scope_enabled  — the persistent enabled set (the CLI filter's bound, and
     *                    the order the historical arms' search asks in).
     *   scope_profiles — the profiles that search asks: -p's where it names any
     *                    (scope_filters_profiles), else the enabled set.
     *   scope_paths    — CLI positional file filter (the range arm's delta
     *                    selection, the commit arm's comparison, and the coverage
     *                    answers both arms with a view give).
     *   the predicates — the workspace arm's presentation (scope_accepts_path,
     *                    scope_accepts_profile) and what its empty line claims
     *                    (scope_filters_profiles, scope_filters_paths).
     */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
        .files         = opts->files,
        .file_count    = opts->file_count,
    };
    error_t err = scope_build(repo, manifest, &scope_inputs, ctx->arena, &scope);
    if (err) return err;

    /* Nothing to diff: said as a failure the run goes past, exit 0, in the words
     * that say whether nothing is enabled or no enabled profile has its branch */
    err = scope_require_enabled(ctx->run.state, scope_enabled(scope), ctx->arena);
    if (err) {
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
        return NULL;
    }

    /* Route to diff implementation based on mode. All historical and workspace
     * paths share ctx->run.content_cache so that unchanged OIDs get cache hits
     * regardless of which path decodes them first. */
    switch (opts->mode) {
        case DIFF_COMMIT_TO_COMMIT:
            /* Diff two commits — historical mode, path filter only */
            return diff_commits(ctx, opts->commit1, opts->commit2, scope, opts);

        case DIFF_COMMIT_TO_WORKSPACE:
            /* Commit-to-workspace — historical mode, path filter only */
            return diff_commit_to_workspace(ctx, opts->commit1, scope, opts);

        case DIFF_WORKSPACE:
            /* Workspace diff — full scope (profile + path dimensions) */
            return diff_workspace(ctx, scope, opts);
    }

    CHECK_ARG(false, "a diff mode no enumerator names");
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/* Command-local positional classes. Start at 1 to reserve 0 for the engine's
 * "unclassified" sentinel (see args.h:args_class_t). */
enum diff_class { DIFF_CLASS_FILE = 1, DIFF_CLASS_GIT_REF, DIFF_CLASS_PROFILE, };

/**
 * Positional classifier for diff.
 *
 * Three-way split, each bucket claimed by a token that announces itself and the
 * last taking what announces nothing:
 *   - Looks like a ref → git_refs[] bucket (diff mode selector).
 *   - Announces a path → files[] bucket (workspace file filter).
 *   - Else             → profiles[] bucket (profile filter).
 *
 * The commit's shape is asked first, so a revision whose pattern holds a glob's
 * bytes — `HEAD^{/fix.*}` — is never read as a path filter. The two shapes meet
 * nowhere else: a token shaped like a commit opens on no '/', '~' or '.' and
 * under no label (base/refspec.h refspec_looks_like_commit, infra/path.h
 * path_input_announces_path).
 *
 * Mode (workspace vs commit-to-workspace vs commit-to-commit) is inferred from
 * the number of git refs in diff_post_parse.
 */
static args_class_t diff_classify(const char *tok) {
    if (refspec_looks_like_commit(tok)) return DIFF_CLASS_GIT_REF;
    if (path_input_announces_path(tok)) return DIFF_CLASS_FILE;
    return DIFF_CLASS_PROFILE;
}

/**
 * Infer mode from git_refs count, validate direction flag only fires in workspace
 * mode. Zero-default on `direction` (DIFF_DIR_UNSET) is the signal that no
 * direction flag was seen; it resolves to DIFF_UPSTREAM as the legacy default.
 */
static error_t diff_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_diff_options_t *o = opts_v;

    switch (o->git_ref_count) {
        case 0:
            o->mode = DIFF_WORKSPACE;
            break;
        case 1:
            o->mode = DIFF_COMMIT_TO_WORKSPACE;
            o->commit1 = o->git_refs[0];
            break;
        case 2:
            o->mode = DIFF_COMMIT_TO_COMMIT;
            o->commit1 = o->git_refs[0];
            o->commit2 = o->git_refs[1];
            break;
        default:
            return error_create(
                ERR_INVALID_ARG,
                "Too many commit references (max 2, got %zu)",
                o->git_ref_count
            );
    }

    bool direction_explicit = (o->direction != DIFF_DIR_UNSET);
    if (direction_explicit && o->mode != DIFF_WORKSPACE) {
        return error_create(
            ERR_INVALID_ARG,
            "Direction flags (--upstream, --downstream, --all) "
            "only apply to workspace diffs"
        );
    }
    if (!direction_explicit) {
        o->direction = DIFF_UPSTREAM;  /* Legacy default. */
    }
    return NULL;
}

/**
 * What can stand at the cursor: an enabled profile, a path of the view (files,
 * and directory claims as subtree filters) or a commit, in any order, as
 * diff_classify routes them — the view and the histories narrowed to the profiles
 * named so far — or a filesystem path.
 */
static args_want_t diff_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    const dotta_ctx_t *ctx = ctx_v;
    const cmd_diff_options_t *o = opts_v;

    if (ARGS_VALUE_IS(at, cmd_diff_options_t, profiles)) {
        completion_profiles(ctx, out, COMPLETION_ENABLED);
        return ARGS_WANT_NONE;
    }

    completion_profiles(ctx, out, COMPLETION_ENABLED);
    completion_files(ctx, out, o->profiles, o->profile_count, true);
    completion_commits(ctx, out, o->profiles, o->profile_count);
    return ARGS_WANT_FILES;
}

static error_t diff_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_diff(ctx, (const cmd_diff_options_t *) opts_v);
}

static const args_opt_t diff_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",       "<name>",
        cmd_diff_options_t,profiles,           profile_count,
        "Filter diff to profile(s) (repeatable)"
    ),
    /* Three direction flags, each writing its enum into the same int. Default
     * (no flag): direction stays at DIFF_DIR_UNSET (0) which diff_post_parse
     * resolves to DIFF_UPSTREAM. */
    ARGS_FLAG_SET(
        "upstream",
        cmd_diff_options_t,direction,          DIFF_UPSTREAM,
        "Preview apply: -/+ is filesystem/repo (default)"
    ),
    ARGS_FLAG_SET(
        "downstream",
        cmd_diff_options_t,direction,          DIFF_DOWNSTREAM,
        "Preview update: -/+ is repo/filesystem"
    ),
    ARGS_FLAG_SET(
        "a all",
        cmd_diff_options_t,direction,          DIFF_BOTH,
        "Show both directions in labelled sections"
    ),
    ARGS_FLAG(
        "name-only",
        cmd_diff_options_t,name_only,
        "Print changed file names only"
    ),
    /* Classified positionals: files go to files[], git refs to git_refs[],
     * everything else to profiles[]. The classify() function above decides. */
    ARGS_POSITIONAL(
        DIFF_CLASS_FILE,   cmd_diff_options_t, files, file_count
    ),
    ARGS_POSITIONAL(
        DIFF_CLASS_GIT_REF,cmd_diff_options_t, git_refs, git_ref_count
    ),
    ARGS_POSITIONAL(
        DIFF_CLASS_PROFILE,cmd_diff_options_t, profiles, profile_count
    ),
    ARGS_END,
};

const args_command_t spec_diff = {
    .name         = "diff",
    .summary      = "Show differences between profiles and filesystem",
    .usage        = "%s diff [options] [<commit>] [<commit>] [<file>...]",
    .description  =
        "Modes:\n"
        "  (no args)             Workspace diff (profile <-> filesystem).\n"
        "  <commit>              Commit -> workspace.\n"
        "  <commit> <commit>     Commit -> commit (must share a profile).\n"
        "  [<file>...]           Restrict any mode to the named files.\n",
    .examples     =
        "  %s diff                          # Preview apply (default)\n"
        "  %s diff --name-only              # Only changed file names\n"
        "  %s diff --downstream             # Preview update\n"
        "  %s diff --all                    # Both directions\n"
        "  %s diff home/.bashrc             # Workspace, single file\n"
        "  %s diff b3e1f9a                  # Commit -> workspace\n"
        "  %s diff HEAD~2 HEAD              # Commit -> commit\n"
        "  %s diff HEAD~1 home/.bashrc      # File at commit vs workspace\n",
    .epilogue     =
        "See also:\n"
        "  %s list <profile> <file>   # Find commit hashes for a file\n"
        "  %s show <commit>           # View commit with diff\n",
    .opts_size    = sizeof(cmd_diff_options_t),
    .opts         = diff_opts,
    .classify     = diff_classify,
    .post_parse   = diff_post_parse,
    .complete     = diff_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
        .mounts   = true,
        .crypto   = DOTTA_CRYPTO_OBTAIN,
        .manifest = true,
    },
    .dispatch     = diff_dispatch,
};
