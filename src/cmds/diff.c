/**
 * diff.c - Show differences between profiles and filesystem
 */

#include "cmds/diff.h"

#include <config.h>
#include <errno.h>
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
 * The line a direction says of a row, or NULL where it lists nothing there
 *
 * What differs, then the act of the verb the direction previews or that verb's
 * refusal, its --force named where one lifts it: the "# Status:" line heading
 * the row's entry, and the listing's one decision — a direction lists a row where
 * it has a line for it, and only there, so no row is listed without a line and
 * no line is said of a row no direction lists. Upstream previews apply at the
 * rows: every row it lands, restores, converges or acknowledges, and every one
 * it skips for --force or for a look that failed. Downstream previews update:
 * every row a local difference or a failed look stands on, which it commits or
 * refuses — a listing that left out a refusal would call "no local changes" over
 * a difference — and never a row only Git moved, nor one nothing looked at, neither
 * carrying a difference of disk's. Read off the row's state and, deployed, its
 * route (core/workspace.h workspace_item_route), each switch exhaustive, so an
 * arm either gains is a build error here.
 *
 * @param item One of the diverged items, a row of the view's (must not be NULL)
 * @param direction The direction asking: one of the two
 * @return The line, or NULL
 */
static const char *diff_status_line(
    const workspace_item_t *item, diff_direction_t direction
) {
    /* --all asks each direction in turn, and post_parse resolves an unset one:
     * a direction is one of the two */
    CHECK_ARG(
        direction == DIFF_UPSTREAM || direction == DIFF_DOWNSTREAM,
        "a diff item is shown for one direction, never both or none"
    );

    switch (item->state) {
        case WORKSPACE_STATE_UNDEPLOYED:
            /* Apply's to create, and nothing stands to differ */
            return direction == DIFF_UPSTREAM
                   ? "not deployed (would be created by apply)"
                   : NULL;

        case WORKSPACE_STATE_DELETED:
            return direction == DIFF_UPSTREAM
                   ? "deleted locally (would be put back by apply)"
                   : "deleted locally (would be committed by update)";

        case WORKSPACE_STATE_DEPLOYED:
            /* Which verb resolves it is the route's, below */
            break;

        case WORKSPACE_STATE_ORPHANED:
        case WORKSPACE_STATE_UNTRACKED:
        case WORKSPACE_STATE_UNSCANNED:
        case WORKSPACE_STATE_RELEASED:
        case WORKSPACE_STATE_OVERRIDDEN:
        case WORKSPACE_STATE_OBSTRUCTING:
            /* No row: diff loads no orphan and runs no scan (diff_workspace) */
            CHECK_ARG(false, "a diff lists the view's rows alone");
    }

    switch (workspace_item_route(item)) {
        case WORKSPACE_ROUTE_DISPLACED_TRACKED:
            /* Beneath a squatted directory, this arm and the three after it:
             * nothing there was looked at, so the path carries no bit to be read
             * off, and the way there is the squatter's own route — the route's
             * four arms, said in a comparison's own words, dotta's own copy in
             * its own state's. The predicate opens the line, as it does on every
             * screen that speaks of such a path (core/workspace.h
             * workspace_displaced_t). Apply writes the row fresh once the squatter
             * goes; downstream lists none, no look having found a difference */
            return direction == DIFF_UPSTREAM
                   ? "not looked at, beneath a squatted directory "
                   "(apply --force <dir> replaces it, then writes this fresh)"
                   : NULL;

        case WORKSPACE_ROUTE_DISPLACED_DERIVED:
            return direction == DIFF_UPSTREAM
                   ? "not looked at, beneath a squatted directory "
                   "('dotta update <dir>' re-derives the way there)"
                   : NULL;

        case WORKSPACE_ROUTE_DISPLACED_STALE:
            return direction == DIFF_UPSTREAM
                   ? "not looked at, beneath a squatted directory changed in Git "
                   "(apply replaces it, then writes this fresh)"
                   : NULL;

        case WORKSPACE_ROUTE_DISPLACED_CONFLICT:
            return direction == DIFF_UPSTREAM
                   ? "not looked at, beneath a squatted directory changed in Git and "
                   "on disk (apply --force <dir> replaces it, then writes this fresh)"
                   : NULL;

        case WORKSPACE_ROUTE_UNVERIFIABLE:
            /* A look that failed: no bit was settled, so no verb's act is true
             * of the path — apply skips the row at preflight, update at its filter.
             * Listed both ways, its fault a difference nobody has ruled out:
             * hiding it said no difference over a file the user had just edited.
             * Worded by whose remedy the failure is (workspace_fault_t), the
             * three words status tags the same row with */
            switch (item->fault) {
                case WORKSPACE_FAULT_LOCKED:
                    return direction == DIFF_UPSTREAM
                           ? "locked (apply skips it)"
                           : "locked (update skips it)";

                case WORKSPACE_FAULT_UNREADABLE:
                    return direction == DIFF_UPSTREAM
                           ? "cannot be read (apply skips it)"
                           : "cannot be read (update skips it)";

                case WORKSPACE_FAULT_UNVERIFIED:
                    return direction == DIFF_UPSTREAM
                           ? "could not be verified (apply skips it)"
                           : "could not be verified (update skips it)";

                case WORKSPACE_FAULT_NONE:
                    CHECK_ARG(false, "an unverifiable item carries its fault");
            }
            break;

        case WORKSPACE_ROUTE_CONFLICT:
            /* Both sides moved: the user's bytes or kind beside a move Git made,
             * to the bytes, the kind or a claim — in the frame's words
             * (core/workspace.h divergence_type_t), as apply's skip label says
             * it. Upstream its --force is qualified: a directory in a blob row's
             * way goes only with all it holds (core/deploy.c check_clearance) */
            if (direction == DIFF_UPSTREAM) {
                return "changed in Git and on disk (apply --force <path> keeps Git's, "
                       "a directory only if all dotta's)";
            }

            /* The user's edit is listed downstream too, which a plain update
             * refuses, its capture committing disk over the move Git made: the
             * --force that commits it where the capture commits the node standing
             * (core/workspace.h workspace_capturable) — exact for the one row —
             * and update's skip where none does, a change across file and
             * directory */
            return workspace_capturable(item)
                   ? "changed in Git and on disk (update --force <path> keeps disk's)"
                   : "changed in Git and on disk (update skips it)";

        case WORKSPACE_ROUTE_STALE:
            /* Git moved and disk did not follow: no local difference, the claims
             * riding apply's — a claim is never an edit (core/deploy.h
             * deploy_content_conflicts) */
            if (direction == DIFF_DOWNSTREAM) return NULL;

            /* Past what dotta last saw — the bytes, or the kind */
            if (item->divergence & DIVERGENCE_STALE) {
                return "changed in Git (would be deployed by apply)";
            }

            /* A claim Git brings alone, which carries no bytes to name: the route's
             * word, then the axes apply changes, in the words status tags the
             * same row with (core/workspace.h divergence_type_t) — both, where
             * both differ, and the ownership where the mode does not, CLAIM_MOVED
             * riding only an axis it attributes. The axes sit in the act, never
             * in what moved: one bit for both axes attributes neither, and beside
             * Git's owner the mode may be the user's, which apply restores all
             * the same */
            if ((item->divergence & DIVERGENCE_MODE) &&
                (item->divergence & DIVERGENCE_OWNERSHIP)) {
                return "changed in Git (mode and ownership would change on apply)";
            }
            if (item->divergence & DIVERGENCE_MODE) {
                return "changed in Git (mode would change on apply)";
            }
            return "changed in Git (ownership would change on apply)";

        case WORKSPACE_ROUTE_KIND:
            /* Another kind the user put there, Git having moved nothing past
             * it: --force's to replace, a directory only with all it holds. Listed
             * both ways, as a conflict is: a user comparing the two sides before
             * choosing one meets it in either direction; downstream, update skips
             * it, no capture committing such a kind */
            return direction == DIFF_UPSTREAM
                   ? "a different kind stands on disk (apply --force <path> keeps Git's, "
                   "a directory only if all dotta's)"
                   : "a different kind stands on disk (update skips it)";

        case WORKSPACE_ROUTE_KIND_DERIVED:
            /* The same at a rung dotta only passes through, which no plan holds,
             * so no flag lifts it: one verb in both directions, the named
             * re-derivation, which retires the claim — in the words status's
             * Squatted ancestors header says it */
            return "a different kind stands at a directory dotta only passes through "
                   "('dotta update <dir>' re-derives it)";

        case WORKSPACE_ROUTE_UNCONFIRMED:
            /* Bytes no base proves: disk is not the row's, and dotta holds no
             * confirmation of what stands there, nor, where it could be asked,
             * did the row's own branch hold disk's bytes at the name
             * (core/workspace.c workspace_ask_bases), so no default's sentence
             * is true of it — apply overwrites it only under --force, and update
             * commits it only under its own. Both directions, in the words status's
             * Unconfirmed header says it; each --force unqualified, as status's
             * Unconfirmed legend line names Git's: a file row with a file or a
             * link standing, a node the capture commits (core/workspace.h
             * workspace_capturable), KIND answering first. Downstream names
             * update's own --force, the verb this direction previews, where
             * status's header names the screens' example for such bytes, a profile
             * of its own */
            return direction == DIFF_UPSTREAM
                   ? "not confirmed by dotta (apply --force <path> keeps Git's)"
                   : "not confirmed by dotta (update --force <path> keeps disk's)";

        case WORKSPACE_ROUTE_CAPTURE:
            /* The user's own, over a base: update's to commit. TYPE never rides
             * beside CONTENT or a claim bit — each analysis ends its measure at
             * another kind — so the word is picked by the bit, the kind first.
             * An edit of the bytes or of the kind apply keeps, overwriting it
             * only under --force (core/deploy.h deploy_content_conflicts) */
            if (item->divergence & DIVERGENCE_TYPE) {
                return direction == DIFF_UPSTREAM
                       ? "type changed locally (apply --force <path> keeps Git's)"
                       : "type changed locally (would be committed by update)";
            }
            if (item->divergence & DIVERGENCE_CONTENT) {
                return direction == DIFF_UPSTREAM
                       ? "modified locally (apply --force <path> keeps Git's)"
                       : "modified locally (would be committed by update)";
            }

            /* A claim alone, named by the axes it differs on in the words status
             * tags the same row with (core/workspace.h divergence_type_t) — both,
             * where both differ — which apply restores unasked, a claim being
             * never an edit, and update commits, as status's legend line for it
             * says */
            if ((item->divergence & DIVERGENCE_MODE) &&
                (item->divergence & DIVERGENCE_OWNERSHIP)) {
                return direction == DIFF_UPSTREAM
                       ? "mode and ownership changed locally (would be restored by apply)"
                       : "mode and ownership changed locally (would be committed by update)";
            }
            if (item->divergence & DIVERGENCE_MODE) {
                return direction == DIFF_UPSTREAM
                       ? "mode changed locally (would be restored by apply)"
                       : "mode changed locally (would be committed by update)";
            }
            if (item->divergence & DIVERGENCE_OWNERSHIP) {
                return direction == DIFF_UPSTREAM
                       ? "ownership changed locally (would be restored by apply)"
                       : "ownership changed locally (would be committed by update)";
            }

            /* The blob's policy alone: how Git stores the content, not a difference
             * between Git and disk — update's to re-store, which no apply touches,
             * so upstream says only the reassignment riding, below */
            if (direction == DIFF_DOWNSTREAM) {
                return "stored plaintext (would be encrypted by update)";
            }
            break;

        case WORKSPACE_ROUTE_REASSIGNED:
            /* The reassignment alone, below */
            break;

        case WORKSPACE_ROUTE_CLEAN:
            CHECK_ARG(false, "a diverged item routes somewhere (workspace_diverged)");
    }

    /* The reassignment apply acknowledges, upstream's alone: the route's own,
     * and the one a capture carries whose one divergence is the blob's policy */
    return direction == DIFF_UPSTREAM &&
           workspace_reassigned(item->row, item->record, item->occupant)
           ? "profile reassigned (acknowledged by apply)"
           : NULL;
}

/**
 * Print a listed row's header: its profile, its name with its kind's slash, and
 * its status line
 *
 * dotta's lines where libgit2's file header would stand, a block of the report's
 * own, asking the boundary above it. Both arms open a listed row with it: the
 * workspace arm above its body (diff_print_item), the commit arm at its patch's
 * file header (diff_print_header_cb) or beside its other verdicts
 * (diff_print_view).
 *
 * @param out Output context (must not be NULL)
 * @param row The row listed (must not be NULL)
 * @param line Its status line (must not be NULL)
 */
static void diff_print_header(output_t *out, const manifest_row_t *row, const char *line) {
    output_gap(out, OUTPUT_NORMAL);

    output_print(
        out, OUTPUT_NORMAL, "{dim}# Profile:{reset} %s\n",
        row->profile
    );
    output_print(
        out, OUTPUT_NORMAL, "{dim}# Path:{reset}    %s%s\n",
        row->storage_path, path_kind_suffix(path_type_kind(row->type))
    );

    /* The status line, uncoloured: an item's colour is its line's, worn on the
     * lists beside the tags it is ranked from (core/workspace.h
     * workspace_item_line) */
    output_print(out, OUTPUT_NORMAL, "{dim}# Status:{reset}  %s\n", line);
}

/**
 * Print the body a row draws where another kind than its own stands: the separator,
 * then both kinds
 *
 * The one found is named off the look that found it — the workspace load's, which
 * no blob read follows, the render's, where a kind raced in since the load
 * (diff_print_item), or the commit arm's own (diff_print_view) — in the sentence
 * every such verdict prints (infra/compare.h compare_type_mismatch).
 *
 * @param out Output context (must not be NULL)
 * @param mode The mode the row expects: a blob's, a link's, or a directory row's
 *             tree
 * @param st The look that found another kind (must not be NULL)
 */
static void diff_print_mismatch(output_t *out, git_filemode_t mode, const struct stat *st) {
    char *mismatch = compare_type_mismatch(mode, st);

    output_print(out, OUTPUT_NORMAL, "{dim}---{reset}\n");
    output_print(out, OUTPUT_NORMAL, "%s\n", mismatch);

    free(mismatch);
}

/**
 * Print one line of a patch as libgit2 hands it, coloured by its origin
 *
 * Nothing is added: a change line that ends without a newline is followed by
 * libgit2's end-of-file line, which opens with the newline that line lacks
 * (lib/libgit2/src/libgit2/diff_xdiff.c git_xdiff_cb), so the lines printed as
 * handed are git's patch, and `git apply` over it gives the side it names. The
 * twin of cmds/show.c show_print_line_cb and cmds/revert.c revert_print_line_cb.
 */
static int diff_print_line_cb(
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

    return 0;
}

/**
 * Print a line of the workspace arm's patch, beneath the header said above it
 *
 * libgit2's file header gives way to the separator: the row's header, said above
 * it from the load, is dotta's, and stands where libgit2's would. Every other
 * line is the twin's (diff_print_line_cb). libgit2 sends the file header once a
 * patch, before its first hunk or binary line, and never for equal sides
 * (lib/libgit2/src/libgit2/diff_print.c flush_file_header), so the separator
 * stands above a body that follows it.
 */
static int diff_print_patch_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    if (line->origin == GIT_DIFF_LINE_FILE_HDR) {
        output_print(payload, OUTPUT_NORMAL, "{dim}---{reset}\n");
        return 0;
    }

    return diff_print_line_cb(delta, hunk, line, payload);
}

/**
 * Print a listed row's entry: its header, and the body it draws
 *
 * Says what the workspace analysis settled; nothing is re-analyzed. The item's
 * row is the path's view row — blob, storage path, profile — which every item
 * diff lists carries (diff_status_line). A look or a read the render makes and
 * fails is the row's: its cause is said in the row's block, and the diff goes on.
 *
 * @param item A listed item (must not be NULL)
 * @param line Its status line for the direction listing it (must not be NULL)
 * @param cache Content cache (must not be NULL)
 * @param direction The direction listing it
 * @param out Output context (must not be NULL)
 */
static void diff_print_item(
    const workspace_item_t *item, const char *line, content_cache_t *cache,
    diff_direction_t direction, output_t *out
) {
    CHECK_NULL(item);
    CHECK_NULL(line);
    CHECK_NULL(cache);
    CHECK_NULL(out);

    const manifest_row_t *row = item->row;

    diff_print_header(out, row, line);

    /* Only a difference of bytes or of kind has something to render: the copy's
     * own edit, the blob or the kind Git moved past, which disk still holds, or
     * the user's own kind. A claim, whoever moved it (CLAIM_MOVED is no byte),
     * a reassignment and how Git stores the blob differ in nothing a hunk could
     * show, and a sealed blob is opened for none of them. The bits are the whole
     * gate: no path bit survives absence or a failed look (core/workspace.h
     * divergence_type_t), whose bytes a read here would fail to reach as the
     * look did, nor stands beneath a squatter (workspace_displaced_t), where
     * Git's blob against the squatter's target's file would be a diff of two
     * unrelated things. */
    if (!(item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_STALE | DIVERGENCE_TYPE))) {
        return;
    }

    git_filemode_t mode = gitops_type_filemode(row->type);

    if (item->occupant != workspace_type_occupant(row->type)) {
        /* Another kind than the row's stands — the user's (TYPE), the node dotta
         * last saw there with Git having moved the path's kind past it (STALE),
         * or the user's beside a move of Git's (both: the conflict, whose line
         * names no kind) — under a file row or a directory row, whose mode is a
         * tree's. The kind is the whole of the difference, said off the load's
         * own look with no blob read: a sealed one, its key cold, would fail a
         * read of bytes that are no part of it. */
        diff_print_mismatch(out, mode, &item->st);
        return;
    }

    /* The row's own kind stood at the load's look, its bytes moved: a file row's
     * alone, a directory row's look at a directory carrying none of the three
     * bits (core/workspace.c workspace_analyze_directory sets TYPE and STALE
     * only over another occupant, CONTENT never). The render's own look, at its
     * moment — the load's is as old as the load and every row printed since,
     * and the read a look bounds stands only behind one taken beside it
     * (infra/compare.c read_copy) — then the row's blob from the cache by its
     * blob_oid (borrowed), read as the entry the row's type says it is, and the
     * copy judged against it off that look. The look or either read can fail
     * where the load's did not — a blob the load never opened, its record's stat
     * vouching for disk or its length disproving it, or the copy read again —
     * and the failure is this row's, as a look the load could not take is its
     * row's: its root, where the hunk would be, as apply's receipt names the
     * same read's. One error per such row stays for the run (base/error.h). */
    struct stat st;
    compare_result_t result;
    error_t err = NULL;

    const fs_occupant_t occupant = fs_lstat_occupant(item->filesystem_path, &st);
    if (occupant == FS_OCCUPANT_UNKNOWN) {
        err = error_errno(errno, "Failed to stat '%s'", item->filesystem_path);
    } else if (occupant == FS_OCCUPANT_NONE) {
        /* Gone since the load: the look says what compare's read would */
        result = CMP_MISSING;
    } else {
        const buffer_t *content = NULL;
        err = content_cache_get_from_blob_oid(
            cache, &row->blob_oid, mode, row->storage_path, row->profile, &content
        );
        if (!err) {
            err = compare_generate_diff(
                content, item->filesystem_path, row->storage_path, mode, &st,
                direction == DIFF_UPSTREAM ? CMP_DIR_UPSTREAM : CMP_DIR_DOWNSTREAM,
                diff_print_patch_cb, out, &result
            );
        }
    }

    if (err) {
        output_print(
            out, OUTPUT_NORMAL, "{dim}# Error:{reset}   %s\n",
            error_message(error_root(err))
        );
        return;
    }

    switch (result) {
        case CMP_EQUAL:
        /* The copy holds the row's bytes after all — a blob Git moved to another
         * id over the same plaintext, a seal made or opened in place, or a copy
         * that moved since the load — and the line stands alone */
        case CMP_DIFFERENT:
            /* Printed beneath the separator, where libgit2's file header stood */
            break;

        case CMP_MISSING:
            output_print(out, OUTPUT_NORMAL, "{dim}---{reset}\n");
            output_print(out, OUTPUT_NORMAL, "File not deployed on disk\n");
            break;

        case CMP_TYPE_DIFF:
            /* Another kind raced in since the load, named off the look that found
             * it */
            diff_print_mismatch(out, mode, &st);
            break;
    }
}

/**
 * List one direction: every diverged row in scope it has a line for
 *
 * The line decides (diff_status_line): a row is listed where its direction says
 * something of it, and the line heads its entry — the settled verdict, and the
 * body its divergence draws, read through the run's content cache — or, under
 * --name-only, the row is its path alone. A listing that names no row says so
 * itself, in what it compared: the rows, in scope wherever a filter narrowed
 * them — never the new files update -n lists, nor the orphans apply -n removes,
 * which diff reads neither of (diff_workspace) — and under --name-only nothing,
 * its names being the whole answer.
 *
 * @param diverged Diverged items from workspace (borrowed slice)
 * @param cache Content cache for blob access (must not be NULL)
 * @param direction Diff direction (UPSTREAM or DOWNSTREAM)
 * @param scope Operation scope (profile + path dimensions; diff has no excludes)
 * @param opts Command options (must not be NULL)
 * @param out Output context (must not be NULL)
 */
static void diff_print_direction(
    workspace_items_t diverged,
    content_cache_t *cache,
    diff_direction_t direction,
    const scope_t *scope,
    const cmd_diff_options_t *opts,
    output_t *out
) {
    CHECK_NULL(cache);
    CHECK_NULL(scope);
    CHECK_NULL(opts);
    CHECK_NULL(out);

    size_t listed = 0;

    /* The comparison opens a block of its own: a name-only listing is one, paid
     * by its first name, and each entry of the patch form one more, its header
     * asking its own (diff_print_header) */
    output_gap(out, OUTPUT_NORMAL);

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* The profile and the path filters, asked as one, the row read by its
         * own kind */
        if (!scope_accepts_path(
            scope, item->profile, item->filesystem_path, item->storage_path, item->item_kind
            )) {
            continue;
        }

        /* The direction's line, or nothing to list */
        const char *line = diff_status_line(item, direction);
        if (!line) continue;

        /* Each entry is a block; a name-only listing's names are one, each with
         * its kind's slash */
        if (opts->form == DIFF_FORM_NAMES) {
            output_print(
                out, OUTPUT_NORMAL, "%s%s\n",
                item->filesystem_path, path_kind_suffix(item->item_kind)
            );
        } else {
            diff_print_item(item, line, cache, direction, out);
        }

        listed++;
    }

    if (listed == 0 && opts->form != DIFF_FORM_NAMES) {
        output_summary(
            out, OUTPUT_NORMAL,
            scope_filters_profiles(scope) || scope_filters_paths(scope)
                ? "No differences in scope"
                : "No differences"
        );
    }
}

/**
 * Write a line of a patch to stdout as libgit2 hands it
 *
 * The payload --raw dedicates stdout to, written past the output layer
 * (base/output.h "Layout and data"): a change line's origin, then its content,
 * nothing added, as the screen's twin prints one (diff_print_line_cb), so the
 * patch is libgit2's byte for byte. The first failed write ends the print, its
 * errno kept in the payload: libgit2 hands the callback's non-zero back as a
 * generic error of its own (lib/libgit2/src/util/errors.h
 * git_error_set_after_callback_function), so why is the payload's to say.
 */
static int diff_write_line_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    int *failed = payload;
    (void) delta;
    (void) hunk;

    /* A change line's origin first, as the twin writes it; each write refused
     * ends the print, its errno read where it fails */
    if (line->origin == GIT_DIFF_LINE_ADDITION ||
        line->origin == GIT_DIFF_LINE_DELETION ||
        line->origin == GIT_DIFF_LINE_CONTEXT) {
        if (fputc(line->origin, stdout) == EOF) {
            *failed = errno;
            return -1;
        }
    }
    if (fwrite(line->content, 1, line->content_len, stdout) != line->content_len) {
        *failed = errno;
        return -1;
    }

    return 0;
}

/**
 * End a patch written for a program: complete, or the run's error with its cause
 *
 * stdout is line-buffered and every patch ends in a newline, so a failed write
 * surfaces at the line it fails on; the last flush is checked all the same, as
 * every payload's end is (cmds/status.c status_write).
 *
 * @param failed The first failed write's errno, or 0
 * @return Error or NULL on success
 */
static error_t diff_write_end(int failed) {
    if (!failed && fflush(stdout) != 0) failed = errno;

    /* The reader's going is no failure: the patch ends where it went */
    if (!failed || failed == EPIPE) return NULL;
    return error_errno(failed, "Failed to write the patch to stdout");
}

/**
 * Write a row's patch to stdout, off the caller's look
 *
 * The row's blob, read as the entry its type says it is, then the copy judged
 * against it off the look, its patch written where the bytes differ
 * (infra/compare.h compare_generate_diff); another kind, a copy gone since the
 * look and one that is the row's write nothing. A read that fails is said on
 * the report's stream, stderr under --raw, and the patch goes on, as the screen's
 * row says its own: "No patch for '<storage path>': <cause>". Its readers are
 * the two arms' writers, diff_write_item and diff_write_view, which hand it the
 * look they took.
 *
 * @param row The row (must not be NULL)
 * @param st The look the caller took at the row's path, of its own kind (must
 *           not be NULL)
 * @param cache Content cache (must not be NULL)
 * @param direction Which side the patch shows first
 * @param out Output context, the report's (must not be NULL)
 * @return 0, or the failed write's errno
 */
static int diff_write_patch(
    const manifest_row_t *row, const struct stat *st, content_cache_t *cache,
    compare_direction_t direction, output_t *out
) {
    git_filemode_t mode = gitops_type_filemode(row->type);
    const buffer_t *content = NULL;
    compare_result_t result;    /* unread: only a difference writes, and its patch says it */
    int failed = 0;

    error_t err = content_cache_get_from_blob_oid(
        cache, &row->blob_oid, mode, row->storage_path, row->profile, &content
    );
    if (!err) {
        err = compare_generate_diff(
            content, row->filesystem_path, row->storage_path, mode, st, direction,
            diff_write_line_cb, &failed, &result
        );
    }

    /* A failed write ends the patch, and the error libgit2 made of it says less
     * than its errno; a failed read is the row's alone */
    if (err && !failed) {
        output_warning(
            out, OUTPUT_NORMAL, "No patch for '%s': %s",
            row->storage_path, error_message(error_root(err))
        );
    }

    return failed;
}

/**
 * Write a listed row's patch for a program: diff_print_item's twin
 *
 * The rows the screen draws a patch for, by its tests: a byte or kind bit, then
 * the row's own kind at the load's look, then the render's own look at its moment,
 * as the screen takes it. A row the load could not look at carries no bit and
 * is said on the report's stream in its status line's words — a difference nobody
 * has ruled out, which a program must not read as none — as is a render's look
 * that failed.
 *
 * @param item A listed item (must not be NULL)
 * @param line Its status line for the direction listing it (must not be NULL)
 * @param cache Content cache (must not be NULL)
 * @param direction The direction listing it
 * @param out Output context, the report's (must not be NULL)
 * @return 0, or the failed write's errno
 */
static int diff_write_item(
    const workspace_item_t *item, const char *line, content_cache_t *cache,
    diff_direction_t direction, output_t *out
) {
    const manifest_row_t *row = item->row;

    if (item->fault != WORKSPACE_FAULT_NONE) {
        output_warning(out, OUTPUT_NORMAL, "No patch for '%s': %s", row->storage_path, line);
        return 0;
    }
    if (!(item->divergence & (DIVERGENCE_CONTENT | DIVERGENCE_STALE | DIVERGENCE_TYPE))) {
        return 0;
    }
    if (item->occupant != workspace_type_occupant(row->type)) return 0;

    struct stat st;
    const fs_occupant_t occupant = fs_lstat_occupant(item->filesystem_path, &st);
    if (occupant == FS_OCCUPANT_UNKNOWN) {
        error_t err = error_errno(errno, "Failed to stat '%s'", item->filesystem_path);
        output_warning(
            out, OUTPUT_NORMAL, "No patch for '%s': %s",
            row->storage_path, error_message(err)
        );
        return 0;
    }
    if (occupant == FS_OCCUPANT_NONE) return 0;

    return diff_write_patch(
        row, &st, cache, direction == DIFF_UPSTREAM ? CMP_DIR_UPSTREAM : CMP_DIR_DOWNSTREAM,
        out
    );
}

/**
 * Write the patches a direction lists, then the patch's end: diff_print_direction's
 * twin
 *
 * The rows the screen lists, by its two tests — the profile and the path filters,
 * asked as one, then the direction's line — each its patch (diff_write_item),
 * and nothing else: no header, sentence, separator or empty line. The stream's
 * state is the first failed write's errno, which ends it.
 *
 * @param diverged Diverged items from workspace (borrowed slice)
 * @param cache Content cache for blob access (must not be NULL)
 * @param direction Diff direction (UPSTREAM or DOWNSTREAM)
 * @param scope Operation scope (profile + path dimensions; diff has no excludes)
 * @param out Output context, the report's (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_write_direction(
    workspace_items_t diverged, content_cache_t *cache, diff_direction_t direction,
    const scope_t *scope, output_t *out
) {
    int failed = 0;

    for (size_t i = 0; !failed && i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        /* The profile and the path filters, asked as one, the row read by its
         * own kind */
        if (!scope_accepts_path(
            scope, item->profile, item->filesystem_path, item->storage_path, item->item_kind
            )) {
            continue;
        }

        /* The direction's line, or nothing to list */
        const char *line = diff_status_line(item, direction);
        if (!line) continue;

        failed = diff_write_item(item, line, cache, direction, out);
    }

    return diff_write_end(failed);
}

/**
 * Print commit header with metadata, a block of its own
 */
static void diff_print_commit(
    output_t *out, const git_commit *commit, const char *profile
) {
    output_gap(out, OUTPUT_NORMAL);

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(commit));

    const git_signature *author = git_commit_author(commit);
    time_t commit_time = (time_t) author->when.time;

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

    /* The date, where a local time places the author's (base/timeutil.h
     * timeutil_absolute) */
    char time_buf[64];
    if (timeutil_absolute(commit_time, time_buf, sizeof(time_buf))) {
        char relative_buf[64];
        timeutil_relative(commit_time, relative_buf, sizeof(relative_buf));

        output_print(
            out, OUTPUT_NORMAL, "{bold}Date:{reset}   %s (%s)\n",
            time_buf, relative_buf
        );
    }
    output_gap(out, OUTPUT_NORMAL);

    /* Commit message (indented). A line and its newline are one step; the last
     * line needs no newline, so a blank line inside a message survives. */
    const char *line = git_commit_message(commit);
    while (*line) {
        size_t len = strcspn(line, "\n");
        output_print(out, OUTPUT_NORMAL, "    %.*s\n", (int) len, line);
        line += len + (line[len] == '\n');
    }
}

/**
 * Print diff statistics
 */
static error_t diff_print_stats(output_t *out, git_diff *diff) {
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
 * The header a row of the commit arm says at its patch's: diff_print_header's
 * three, held until libgit2 prints the patch's file header (diff_print_header_cb)
 */
typedef struct {
    output_t *out;
    const manifest_row_t *row;      /* the row whose patch prints */
    const char *line;               /* its status line */
} diff_header_t;

/**
 * Print a line of the commit arm's patch, its row's header said at libgit2's
 *
 * A commit's row is listed by what its comparison found, and a difference of
 * bytes is found only as its patch prints: libgit2's file header is the first
 * line of every patch with a body and of no other (lib/libgit2/src/libgit2/
 * diff_print.c flush_file_header), so the row's header is said there, the one
 * place a difference is known before its first line. Then every line goes as
 * the workspace arm's does (diff_print_patch_cb): the separator where libgit2's
 * file header stood, the rest as libgit2 hands it.
 */
static int diff_print_header_cb(
    const git_diff_delta *delta,
    const git_diff_hunk *hunk,
    const git_diff_line *line,
    void *payload
) {
    const diff_header_t *header = payload;

    if (line->origin == GIT_DIFF_LINE_FILE_HDR) {
        diff_print_header(header->out, header->row, header->line);
    }

    return diff_print_patch_cb(delta, hunk, line, header->out);
}

/**
 * Whether the record vouches that the copy at a commit's row is the row's own,
 * its blob unread
 *
 * The workspace's base fast path, asked of a commit's row: the record at the
 * row's path confirmed the row's very blob, as its kind (core/workspace.h
 * workspace_base, workspace_compare_confirmed), and the row's look — the caller's,
 * which found the row's kind — stands behind the triple taken at that confirmation
 * (core/state.h state_stat_matches), so disk holds those bytes and nothing need
 * be read to say so. A sealed blob's id names its binding, so a record of another
 * binding vouches for one only where it was forged (stated). Its readers are
 * the commit arm's two printers, diff_print_view's forms and diff_write_view,
 * each off the one look a row takes.
 *
 * @param row The commit's row (must not be NULL)
 * @param record The record at its path, or NULL
 * @param st The row's look, which found the row's kind (must not be NULL)
 * @return Whether the copy is the commit's, by the record alone
 */
static bool diff_vouched(
    const manifest_row_t *row, const state_record_t *record, const struct stat *st
) {
    return workspace_base(record) &&
           workspace_compare_confirmed(row, record) == CMP_EQUAL &&
           state_stat_matches(record, st);
}

/**
 * Compare a commit's view against the current filesystem
 *
 * The commit-to-workspace comparison: every file row of the view
 * manifest_build_profile computed from the profile at the commit, compared against
 * what stands at its path now — the profile's own places settled, so a file of
 * it beneath its own standing blob is no row, nor a blob that lost its place to
 * its claims beneath. A directory row — a claim of the tree's own metadata.json,
 * or the layer's rung at a lost blob's place — has no content to diff and is
 * passed over by its type, the test core/manifest.h leaves to a reader that wants
 * files: its claim goes uncompared, as every claim does here (stated), where
 * the workspace arm lists it. Each row carries the profile whose claim it is,
 * the commit's, and its blob opens under the row's own binding. A comparison
 * that names no row says so itself, as the workspace arm's listing does: in scope
 * under a filter, which passed over every row outside it, else of the whole;
 * under --name-only nothing, its names being the whole answer.
 *
 * A row is looked at once, before its blob is read: an absence and another kind
 * are said off the look, so no blob is read where no bytes could be compared —
 * a sealed one's key never asked for — and a look of the row's own kind is what
 * the comparison judges, its patch printed beneath the row's header, which a
 * difference of bytes says at the patch's own file header (diff_print_header_cb).
 * An absence is worded by the record at its path: "deleted locally" where this
 * profile's record confirmed bytes there, "not deployed" for a file this machine
 * never had. And a copy of the row's own kind the record vouches for is the
 * commit's, its blob unread (diff_vouched): an unchanged tree reads no blob,
 * and a cold key is asked for only where a sealed file changed since the commit.
 * A look or a read that fails is the row's — its header says the failure's class
 * over its cause — and the comparison goes on; under --name-only the row is listed.
 * A print that fails once its patch began says the row's header twice, at the
 * patch's file header and over the failure: libgit2's own failure to format a
 * patch it holds, no ordinary path (stated).
 *
 * @param view The commit's view (must not be NULL; its rows are the command arena's
 *             and live until command end)
 * @param path_filter Path filter for CLI (can be NULL for no filter)
 * @param opts Command options (must not be NULL)
 * @param cache Shared content cache (the run's, must not be NULL)
 * @param records The record's snapshot (core/state.h state_records; NULL when
 *                record_count is 0)
 * @param record_count Records in it
 * @param out Output context (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_print_view(
    const manifest_t *view, const pathspec_t *path_filter, const cmd_diff_options_t *opts,
    content_cache_t *cache, const state_record_t *records, size_t record_count,
    output_t *out
) {
    CHECK_NULL(view);
    CHECK_NULL(opts);
    CHECK_NULL(cache);
    CHECK_NULL(out);

    size_t listed = 0;

    /* The comparison opens a block of its own: a name-only listing is one, paid
     * by its first name, and each entry of the patch form one more, its header
     * asking its own (diff_print_header) */
    output_gap(out, OUTPUT_NORMAL);

    manifest_rows_t rows = manifest_rows(view);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

        /* A directory row: no content to diff */
        if (row->type == PATH_TYPE_DIRECTORY) continue;

        /* Check the path filter */
        if (!pathspec_matches(
            path_filter, row->filesystem_path, row->storage_path, PATH_KIND_FILE
            )) {
            continue;
        }

        git_filemode_t mode = gitops_type_filemode(row->type);
        const state_record_t *record = state_find_record(
            records, record_count, row->filesystem_path
        );
        struct stat st;

        /* Name-only output */
        if (opts->form == DIFF_FORM_NAMES) {
            /* One look, handed to the comparison below rather than left for it
             * to take one of its own: the lstat names the path itself (a broken
             * symlink is present — only its target is absent), and every answer
             * but the row's own kind — nothing standing, another kind, a look
             * that failed — is a difference named before a blob is loaded, there
             * being nothing to compare against. So this form asks its question
             * through the window the patch form has — one look, then the read
             * off it — where it used to look twice and could see two different
             * worlds. */
            if (fs_lstat_occupant(row->filesystem_path, &st) ==
                workspace_type_occupant(row->type)) {
                /* The record vouches for the commit's own copy: nothing to read */
                if (diff_vouched(row, record, &st)) continue;

                /* The commit's bytes against disk's; a read that fails lists
                 * the row, a difference nobody has ruled out, as the patch form
                 * says it and as a look that failed is listed */
                const buffer_t *content = NULL;
                compare_result_t result;
                error_t err = content_cache_get_from_blob_oid(
                    cache, &row->blob_oid, mode, row->storage_path, row->profile, &content
                );
                if (!err) {
                    err = compare_buffer_to_disk(
                        content, row->filesystem_path, mode, &st, &result
                    );
                }
                if (!err && result == CMP_EQUAL) continue;
            }

            output_print(out, OUTPUT_NORMAL, "%s\n", row->filesystem_path);
            listed++;
            continue;
        }

        /* The patch form: the row's look, ahead of its blob, asked as the
         * workspace's file analysis asks its own — an absence and another kind
         * are said off it with nothing read, as the name-only form names them,
         * and a copy the record vouches for is the commit's — then the blob,
         * and the comparison off that look, which prints the patch where the
         * bytes differ: the bytes judged are the bytes printed. Handed only a
         * look of the row's own kind, compare's kind rung stands, so another
         * kind is this look's alone to say. */
        compare_result_t result;
        error_t err = NULL;

        const fs_occupant_t occupant = fs_lstat_occupant(row->filesystem_path, &st);
        if (occupant == FS_OCCUPANT_UNKNOWN) {
            err = error_errno(errno, "Failed to stat '%s'", row->filesystem_path);
        } else if (occupant == FS_OCCUPANT_NONE) {
            result = CMP_MISSING;
        } else if (occupant != workspace_type_occupant(row->type)) {
            result = CMP_TYPE_DIFF;
        } else if (diff_vouched(row, record, &st)) {
            /* The record vouches for the commit's own copy, in compare's words:
             * what a read would have found, with nothing read */
            result = CMP_EQUAL;
        } else {
            const buffer_t *content = NULL;
            err = content_cache_get_from_blob_oid(
                cache, &row->blob_oid, mode, row->storage_path, row->profile, &content
            );
            if (!err) {
                /* The header a difference of bytes says, at its patch's */
                diff_header_t header = {
                    .out = out, .row = row, .line = "modified locally since commit"
                };
                err = compare_generate_diff(
                    content, row->filesystem_path, row->storage_path, mode, &st,
                    CMP_DIR_DOWNSTREAM, diff_print_header_cb, &header, &result
                );
            }
        }

        if (err) {
            /* The row's look or a read failed — a component the run may not search,
             * a cold key, a seal this build cannot open — and the row is said
             * by whose remedy that is (core/workspace.h workspace_code_fault),
             * in the words diff's status line says it with, over the failure's
             * root: the row's alone, and the comparison goes on, as the workspace
             * arm's render says its own. One error per such row stays for the
             * run (base/error.h); a cold key is one, the keymgr's standing refusal
             * answering every row after the first */
            switch (workspace_code_fault(error_code(err))) {
                case WORKSPACE_FAULT_LOCKED:
                    diff_print_header(out, row, "locked");
                    break;

                case WORKSPACE_FAULT_UNREADABLE:
                    diff_print_header(out, row, "cannot be read");
                    break;

                case WORKSPACE_FAULT_UNVERIFIED:
                    diff_print_header(out, row, "could not be verified");
                    break;

                case WORKSPACE_FAULT_NONE:
                    CHECK_ARG(false, "a failed read classed from no failure");
            }
            output_print(
                out, OUTPUT_NORMAL, "{dim}# Error:{reset}   %s\n",
                error_message(error_root(err))
            );

            listed++;
            continue;
        }

        /* The verdict, in the commit's words: a copy that is the commit's prints
         * nothing at all, and a difference of bytes said its header at its
         * patch's */
        switch (result) {
            case CMP_EQUAL:
                continue;

            case CMP_DIFFERENT:
                break;

            case CMP_MISSING:
                /* Whose the absence is, by the record at its path: this profile's
                 * record that confirmed bytes there is a file the user had and
                 * deleted, and any other absence is a file this machine never
                 * had — core/workspace.c classify_absent's rule, less its stale
                 * clause: a record that confirmed a later blob than the commit's
                 * still says the user had the file */
                diff_print_header(
                    out, row,
                    workspace_base(record) && strcmp(record->profile, row->profile) == 0
                        ? "deleted locally (file missing)"
                        : "not deployed (file missing)"
                );
                break;

            case CMP_TYPE_DIFF:
                /* Both kinds, off the look that found another */
                diff_print_header(out, row, "type changed locally");
                diff_print_mismatch(out, mode, &st);
                break;
        }

        listed++;
    }

    if (listed == 0 && opts->form != DIFF_FORM_NAMES) {
        output_summary(
            out, OUTPUT_NORMAL,
            path_filter
                ? "No differences in scope"
                : "No differences between commit and workspace"
        );
    }

    return NULL;
}

/**
 * Write a commit's patches for a program: diff_print_view's twin
 *
 * The file rows in the filter, each by the screen's ladder off its one look: a
 * look that fails is said on the report's stream, stderr under --raw, as the
 * screen's row says it; an absence, another kind and a copy the record vouches
 * for have no patch; every other row is read and its patch written, the commit's
 * side first (diff_write_patch). The rows in the commit's tree order, as the
 * screen lists them; then the patch's end.
 *
 * @param view The commit's view (must not be NULL)
 * @param path_filter Path filter for CLI (can be NULL for no filter)
 * @param cache Shared content cache (the run's, must not be NULL)
 * @param records The record's snapshot (core/state.h state_records; NULL when
 *                record_count is 0)
 * @param record_count Records in it
 * @param out Output context, the report's (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_write_view(
    const manifest_t *view, const pathspec_t *path_filter, content_cache_t *cache,
    const state_record_t *records, size_t record_count, output_t *out
) {
    int failed = 0;

    manifest_rows_t rows = manifest_rows(view);
    for (size_t i = 0; !failed && i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];

        /* A directory row: no content to diff */
        if (row->type == PATH_TYPE_DIRECTORY) continue;

        /* Check the path filter */
        if (!pathspec_matches(
            path_filter, row->filesystem_path, row->storage_path, PATH_KIND_FILE
            )) {
            continue;
        }

        const state_record_t *record = state_find_record(
            records, record_count, row->filesystem_path
        );
        struct stat st;

        const fs_occupant_t occupant = fs_lstat_occupant(row->filesystem_path, &st);
        if (occupant == FS_OCCUPANT_UNKNOWN) {
            error_t err = error_errno(errno, "Failed to stat '%s'", row->filesystem_path);
            output_warning(
                out, OUTPUT_NORMAL, "No patch for '%s': %s",
                row->storage_path, error_message(err)
            );
            continue;
        }

        /* An absence, another kind and a copy the record vouches for: no patch */
        if (occupant != workspace_type_occupant(row->type) || diff_vouched(row, record, &st)) {
            continue;
        }

        failed = diff_write_patch(row, &st, cache, CMP_DIR_DOWNSTREAM, out);
    }

    return diff_write_end(failed);
}

/**
 * Say what the path filter's entries missed, and whether any reached a path
 *
 * One block, its boundary asked by its first line: each entry no path of the
 * arm's own reached (core/scope.h scope_coverage_misses) — which likely indicates
 * a typo — warned in the words of what the arm's paths are: the enabled view's
 * are active paths, a commit's are the commit's, a range's either commit's, and
 * a miss in one says nothing of the others. An entry that reached only paths of
 * a profile -p leaves out names the first one's profile.
 *
 * @param out Output context for the answers
 * @param scope The run's scope, the entries of whose paths the misses are counted
 *              against (core/scope.h scope_path_count; must not be NULL)
 * @param coverage The arm's coverage, its paths handed in (must not be NULL)
 * @param what What the arm's paths are on the screen (must not be NULL)
 * @return false where no entry reached a path — nothing under the filter can
 *         diff, and the answers are the whole report; true otherwise, and always
 *         under no filter
 */
static bool diff_print_coverage(
    output_t *out, const scope_t *scope, const scope_coverage_t *coverage, const char *what
) {
    scope_misses_t misses = scope_coverage_misses(coverage);
    if (misses.count > 0) output_gap(out, OUTPUT_NORMAL);

    for (size_t i = 0; i < misses.count; i++) {
        const scope_miss_t *miss = &misses.entries[i];
        if (miss->hidden) {
            output_warning(
                out, OUTPUT_NORMAL, "No %s matches %s'%s' (%s's, hidden by the profile filter)",
                what, miss->entry.rule ? "pattern " : "", miss->entry.text, miss->hidden
            );
        } else {
            output_warning(
                out, OUTPUT_NORMAL, "No %s matches %s'%s'", what,
                miss->entry.rule ? "pattern " : "", miss->entry.text
            );
        }
    }

    return misses.count == 0 || misses.count < scope_path_count(scope);
}

/**
 * Answer the path filter's coverage over a view
 *
 * Every row of the view handed to the scope's coverage (core/scope.h
 * scope_coverage_add) — by both its names, each entry reading the one in its
 * own vocabulary, and by its own kind, read off its type — until every entry
 * has reached one; then the misses said (diff_print_coverage). An entry that
 * reaches a row has something to compare, a directory row as a file row, and is
 * not answered.
 *
 * One implementation serves both arms that compare against a view: the commit
 * arm's is the one manifest_build_profile computes from the profile at the commit,
 * a profile -p names where it names any, so no row of it is hidden; the workspace
 * arm's the one the dispatcher built and the workspace joins, whose rows of a
 * profile -p leaves out answer nothing. Coverage is a question about the view
 * alone — nothing here takes a look — so each arm asks it before anything is
 * compared or printed: an entry is answered beside a diff as well as in place
 * of one, and the answer is the same under --name-only. The commit arm compares
 * a file row's content and kind alone (diff_print_view), so an entry reaching
 * only directory rows finds no difference in scope there, their claims uncompared
 * as every claim is in that arm (stated).
 *
 * @param scope The run's scope: its path filter, and -p beside it (must not be
 *              NULL)
 * @param view The view the arm compares against (must not be NULL)
 * @param what What the view's paths are on the screen: "active path" for the
 *             enabled view, "path of the commit" for one commit's (must not be
 *             NULL)
 * @param arena Arena the coverage lives in: the command's (must not be NULL)
 * @param out Output context for the answers
 * @return false where no entry reaches a row — nothing under the filter can diff,
 *         and the answers are the whole report; true otherwise, and always under
 *         no filter
 */
static bool diff_validate_filter(
    const scope_t *scope, const manifest_t *view, const char *what, arena_t *arena,
    output_t *out
) {
    scope_coverage_t *coverage = scope_coverage_create(scope, arena);

    manifest_rows_t rows = manifest_rows(view);
    for (size_t i = 0; i < rows.count; i++) {
        const manifest_row_t *row = rows.entries[i];
        if (!scope_coverage_add(
            coverage, row->profile, row->filesystem_path, row->storage_path,
            path_type_kind(row->type)
            )) {
            break;
        }
    }

    return diff_print_coverage(out, scope, coverage, what);
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
 * is derived from scope_paths (raw CLI positional args, never narrowed), and
 * its coverage over the commit's view is answered before anything else is printed,
 * a filter under which nothing can diff ending the diff at its answers
 * (diff_validate_filter).
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
    const dotta_ctx_t *ctx, const char *commit_ref, const scope_t *scope,
    const cmd_diff_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(commit_ref);
    CHECK_NULL(scope);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;
    const mount_table_t *mounts = ctx->run.mounts;
    content_cache_t *cache = ctx->run.content_cache;
    arena_t *arena = ctx->arena;
    output_t *out = ctx->out;

    /* The profiles the commit is looked for in: the enabled set, narrowed to
     * the ones -p names where it names any (the scope's face is exactly that
     * set, and its shape says whether it names any: diff names no profile:path). */
    const string_array_t *searched = scope_profiles(scope);
    const string_array_t *filter = scope_filters_profiles(scope) ? searched : NULL;
    const pathspec_t *path_filter = scope_paths(scope);

    error_t err = NULL;
    git_commit *commit = NULL;
    const char *name = NULL;  /* borrowed from the enabled set */

    /* Step 1: Resolve commit to find which profile contains it. The search answers
     * for every profile ahead of the holder, so a profile that will not read
     * cancels the diff rather than let a later one answer in its place
     * (core/scope.h scope_resolve_commit). */
    err = scope_resolve_commit(
        repo, scope_enabled(scope), filter, commit_ref, &commit, &name
    );
    if (err) goto cleanup;

    char oid_str[8];
    git_oid_tostr(oid_str, sizeof(oid_str), git_commit_id(commit));

    /* Step 2: Build the historical view: the profile at THE HISTORICAL COMMIT
     * (not HEAD!), built into a view and let go — a tree that will not read refused
     * by the open, naming the commit (core/profiles.h profile_open).
     *
     * The tree's own claim sheet is the profile's to read (core/profiles.h), so
     * the historical rows carry the modes and stamps that commit claimed, and a
     * sheet that will not load refuses the diff instead of showing Git's defaults
     * as though nothing had been claimed.
     *
     * The view is allocated into the borrowed command arena; it outlives every
     * reader below, then lives until command end. */
    manifest_t *historical = NULL;
    profile_t *profile = NULL;
    err = profile_open(name, commit, &profile);
    if (!err) err = manifest_build_profile(profile, mounts, arena, &historical);
    profile_free(profile);
    if (err) goto cleanup;

    /* Step 3: The record, read once for every row: whose an absence is, and which
     * copies are the commit's unread, by the record at each row's path */
    state_record_t *records = NULL;
    size_t record_count = 0;
    err = state_records(state, arena, &records, &record_count);
    if (err) goto cleanup;

    /* Step 4: What the run prints, chosen once its facts are in hand, so a commit
     * whose tree or sheet will not read is refused with nothing above it. First
     * the filter's coverage over the commit's view, before anything is compared,
     * as the workspace arm answers it over its own: where no entry reaches a
     * row, nothing can diff, and the answers are the whole report. */
    if (!diff_validate_filter(scope, historical, "path of the commit", arena, out)) {
        goto cleanup;
    }

    switch ((diff_form_t) opts->form) {
        case DIFF_FORM_RAW:
            /* libgit2's patches alone, for a program */
            err = diff_write_view(
                historical, path_filter, cache, records, record_count, out
            );
            break;

        case DIFF_FORM_NAMES:
        case DIFF_FORM_PATCH:
            /* Warn when more than one profile was searched: only the profile
             * containing the commit is compared against the filesystem. A block
             * of its own, beneath the coverage's answers where any stand. */
            if (searched->count > 1) {
                output_gap(out, OUTPUT_NORMAL);
                output_info(
                    out, OUTPUT_NORMAL, "Note: comparing commit against profile '%s' only "
                    "(commit-to-workspace compares one profile at a time)", name
                );
            }

            output_gap(out, OUTPUT_NORMAL);
            output_print(
                out, OUTPUT_NORMAL, "{bold}diff --dotta %s..workspace{reset}\n",
                oid_str
            );

            diff_print_commit(out, commit, name);

            /* The comparison saying its own empty line */
            err = diff_print_view(
                historical, path_filter, opts, cache, records, record_count, out
            );
            break;
    }

cleanup:
    git_commit_free(commit);

    return err;
}

/**
 * The selection of a commit range under the path filter: what its two readers read
 *
 * The filter's two questions of a name of the range, one a reader — which entries
 * it reaches, each name either tree holds handed to the coverage before the diff
 * is generated (diff_cover_entry_cb), and whether the filter selects it, each
 * delta asked as the diff is (diff_select_delta_cb) — and what a name is resolved
 * through for both: the profile the range belongs to and this machine's table,
 * under which a past tree's names are placed where the binding stands now, as
 * the commit-to-workspace arm places them (manifest_build_profile).
 */
typedef struct {
    scope_coverage_t *coverage;     /* the entries a name of either tree reaches */
    const pathspec_t *filter;       /* never NULL: both readers run under a filter alone */
    const mount_table_t *mounts;
    const char *profile;
    arena_t *arena;                 /* the paths' lifetime: the command's */
} diff_selection_t;

/**
 * Hand one name of a commit range's tree to the path filter's coverage
 *
 * A tree walk's visitor (sys/gitops.h gitops_tree_walk), over each of the range's
 * two trees before the diff is generated: every name the diff could hold a delta
 * for — an entry under a label that is no tree, a blob of any filemode and a
 * gitlink alike, each of which a tree-to-tree diff spells a delta of
 * (lib/libgit2/src/libgit2/diff_generate.c handle_unmatched_new_item,
 * maybe_modified) — placed as its delta would be, and read as a file, as the
 * delta is (diff_select_delta_cb). A tree is walked into, and one no label names
 * skipped with everything beneath it: the content gate every walk over a profile's
 * tree asks (infra/label.h label_prefixes). The walk ends once every entry of
 * the filter has reached a name.
 *
 * @param path    The entry's name in the tree, joined by the walk
 * @param entry   The entry
 * @param payload The selection (diff_selection_t)
 * @param next    What the walk does next: STOP once every entry is reached
 * @return NULL: nothing here fails
 */
static error_t diff_cover_entry_cb(
    const char *path, const git_tree_entry *entry, void *payload, gitops_next_t *next
) {
    diff_selection_t *sel = payload;

    if (!label_prefixes(path)) {
        *next = GITOPS_NEXT_SKIP;
        return NULL;
    }
    if (git_tree_entry_type(entry) == GIT_OBJECT_TREE) return NULL;

    const char *filesystem_path = mount_resolve(sel->arena, sel->mounts, sel->profile, path);

    if (!scope_coverage_add(sel->coverage, sel->profile, filesystem_path, path, PATH_KIND_FILE)) {
        *next = GITOPS_NEXT_STOP;
    }
    return NULL;
}

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
 * @param payload  The selection (diff_selection_t)
 * @return 0 to keep the delta, 1 to drop it
 */
static int diff_select_delta_cb(
    const git_diff *diff, const git_diff_delta *delta, const char *matched,
    void *payload
) {
    (void) diff;
    (void) matched;

    diff_selection_t *sel = payload;
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
 * delta by delta as the diff is generated (diff_select_delta_cb, each delta by
 * both its names under this machine's table), so the diff printed — names, stats,
 * patch — is the selection and nothing else.
 *
 * Each entry of the filter is answered before the diff is generated, over the
 * range's own paths: every name either commit holds that a delta could be, placed
 * as a delta is (diff_cover_entry_cb) — so an entry naming a path both commits
 * hold unchanged has reached it, and one naming a path neither holds is warned,
 * first, and alone where no entry reached a path, as the commit arm answers over
 * its view (diff_validate_filter). The range is the profile -p names where it
 * names any, so no path of it is hidden. No sheet is read: a range across a sheet
 * an older schema wrote is answered and diffed under a filter as under none.
 * And a directory claim a sheet alone holds — one tracked with nothing beneath
 * it, which no tree holds — is no path of either commit: under a filter the sheet's
 * own changes are out of the range (diff_select_delta_cb), so nothing there is
 * compared.
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
    const dotta_ctx_t *ctx, const char *commit1_ref, const char *commit2_ref,
    const scope_t *scope, const cmd_diff_options_t *opts
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

    /* The profiles -p names, or NULL: every enabled one — the scope's face and
     * its shape, diff naming no profile:path */
    const string_array_t *filter = scope_filters_profiles(scope)
        ? scope_profiles(scope) : NULL;
    const pathspec_t *path_filter = scope_paths(scope);

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

    char oid1_str[8], oid2_str[8];
    git_oid_tostr(oid1_str, sizeof(oid1_str), git_commit_id(commit1));
    git_oid_tostr(oid2_str, sizeof(oid2_str), git_commit_id(commit2));

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

    /* The selection, borrowed by both its readers: the walks below, and libgit2,
     * which reads the payload only while generating */
    diff_selection_t selection = {
        .coverage = scope_coverage_create(scope, arena),
        .filter   = path_filter,
        .mounts   = mounts,
        .profile  = profile,
        .arena    = arena
    };

    /* Under a filter, each entry answered first, over the range's own paths:
     * the two trees walked, each only until every entry has reached a path, and
     * the misses said before anything else — where no entry reached one, nothing
     * can diff, and the answers are the whole report. Then the diff, the filter
     * selecting each delta on its way in. */
    git_diff_options diff_opts;
    git_diff_options_init(&diff_opts, GIT_DIFF_OPTIONS_VERSION);
    if (path_filter) {
        err = gitops_tree_walk(tree1, diff_cover_entry_cb, &selection);
        if (!err) err = gitops_tree_walk(tree2, diff_cover_entry_cb, &selection);
        if (err) goto cleanup;

        if (!diff_print_coverage(out, scope, selection.coverage, "path of either commit")) {
            goto cleanup;
        }

        diff_opts.notify_cb = diff_select_delta_cb;
        diff_opts.payload = &selection;
    }

    err = gitops_diff_trees(repo, tree1, tree2, &diff_opts, &diff);
    if (err) goto cleanup;

    /* What the run prints, chosen once the diff is in hand */
    switch ((diff_form_t) opts->form) {
        case DIFF_FORM_RAW: {
            /* libgit2's patch whole, for a program: the first failed write's
             * errno ends it, and libgit2's own error over that write says less */
            int failed = 0;
            rc = git_diff_print(diff, GIT_DIFF_FORMAT_PATCH, diff_write_line_cb, &failed);
            err = rc < 0 && !failed ? error_git(rc, "Cannot print the diff")
                                    : diff_write_end(failed);
            break;
        }

        case DIFF_FORM_NAMES:
        case DIFF_FORM_PATCH:
            output_gap(out, OUTPUT_NORMAL);
            output_print(
                out, OUTPUT_NORMAL, "{bold}diff --dotta %s..%s{reset}\n",
                oid1_str, oid2_str
            );

            /* Print second commit header (the "new" one) */
            diff_print_commit(out, commit2, profile);

            /* The range's body, a block beneath the header: the names, or the
             * statistics above the patch */
            output_gap(out, OUTPUT_NORMAL);
            if (opts->form == DIFF_FORM_NAMES) {
                /* Name-only: each changed path, cyan, as the patch's file header
                 * colours it — written here as the datum it is, never libgit2's
                 * name-only line, which is the path raw where git quotes it
                 * (lib/libgit2/src/libgit2/ diff_print.c diff_print_one_name_only).
                 * Every delta is a change: a tree-to-tree diff drops an unmodified
                 * one unless INCLUDE_UNMODIFIED is asked (diff_generate.c
                 * diff_delta__from_two), and dotta never asks it. */
                size_t count = git_diff_num_deltas(diff);
                for (size_t i = 0; i < count; i++) {
                    const git_diff_delta *delta = git_diff_get_delta(diff, i);
                    output_colored(
                        out, OUTPUT_NORMAL, OUTPUT_COLOR_CYAN, "%s\n",
                        delta->new_file.path
                    );
                }
            } else {
                /* The patch form: statistics followed by patch */
                err = diff_print_stats(out, diff);
                if (err) goto cleanup;

                output_gap(out, OUTPUT_NORMAL);

                rc = git_diff_print(diff, GIT_DIFF_FORMAT_PATCH, diff_print_line_cb, out);
                if (rc < 0) {
                    err = error_git(rc, "Cannot print the diff");
                    goto cleanup;
                }
            }
            break;
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
 * (diff_validate_filter). Otherwise the workspace is loaded over the same view,
 * its learning flushed, and the diverged items presented per direction under
 * the scope, each listing saying its own empty line (diff_print_direction) —
 * the analysis settled every verdict, and nothing here re-reads one.
 *
 * @param ctx Dispatch context (must not be NULL; reads the repository, the borrowed
 *            state handle, the shared blob-content cache, and the view over the
 *            enabled set)
 * @param scope Operation scope — profile and path filters (must not be NULL)
 * @param opts Command options (must not be NULL)
 * @return Error or NULL on success
 */
static error_t diff_workspace(
    const dotta_ctx_t *ctx, const scope_t *scope, const cmd_diff_options_t *opts
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
     * and all the question needs, a row of a profile -p leaves out reaching no
     * entry. Where no entry reaches a row, nothing can diff, the answers are
     * the whole report, and no workspace is loaded. */
    if (!diff_validate_filter(scope, manifest, "active path", arena, out)) {
        return NULL;
    }

    /* Step 2: Load the workspace over the rows alone. What apply would remove
     * is apply -n's to preview, and the new files update -n's, so no orphan is
     * analyzed and no scan is run. */
    workspace_options_t ws_opts = {
        .analyze_orphans   = false,
        .analyze_untracked = false
    };

    workspace_t *ws = NULL;
    error_t err = workspace_load(
        repo, state, config, cache, manifest, &ws_opts, arena, &ws
    );
    if (err) return err;

    /* Step 3: Get pre-analyzed divergence from workspace */
    workspace_items_t diverged = workspace_diverged(ws);

    /* Step 4: What the run prints, chosen once the diverged items are in hand:
     * the patches alone, for a program, or the listings, by direction, each saying
     * its own empty line. A row the analysis could not look at is listed by its
     * status line, which names its class, so no listing is empty over it; under
     * --raw it is said on stderr (diff_write_item). */
    switch ((diff_form_t) opts->form) {
        case DIFF_FORM_RAW:
            /* One direction: --all is refused beside --raw (diff_post_parse) */
            return diff_write_direction(diverged, cache, opts->direction, scope, out);

        case DIFF_FORM_NAMES:
        case DIFF_FORM_PATCH:
            if (opts->direction == DIFF_BOTH) {
                /* Both directions under their headers, the upstream section first */
                output_section(out, OUTPUT_NORMAL, "Upstream (repository → filesystem)");
                output_info(out, OUTPUT_NORMAL, "Shows what 'dotta apply' would change");
                diff_print_direction(diverged, cache, DIFF_UPSTREAM, scope, opts, out);

                output_section(out, OUTPUT_NORMAL, "Downstream (filesystem → repository)");
                output_info(out, OUTPUT_NORMAL, "Shows what 'dotta update' would commit");
                diff_print_direction(diverged, cache, DIFF_DOWNSTREAM, scope, opts, out);
            } else {
                diff_print_direction(diverged, cache, opts->direction, scope, opts, out);
            }
            return NULL;
    }

    CHECK_ARG(false, "a diff form no enumerator names");
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

    /* --raw dedicates stdout to the patch: every line dotta says — the scope's
     * refusal, the filter's coverage answers, a row it has no patch for — goes
     * to stderr, moved before one can land (base/output.h output_set_stream) */
    if (opts->form == DIFF_FORM_RAW) output_set_stream(out, stderr);

    /* Build operation scope
     *
     *   scope_enabled  — the persistent enabled set (the CLI filter's bound, and
     *                    the order the historical arms' search asks in).
     *   scope_profiles — the profiles that search asks: -p's where it names any
     *                    (scope_filters_profiles), else the enabled set.
     *   scope_paths    — CLI positional path filter (the range arm's delta
     *                    selection, the commit arm's comparison).
     *   the coverage   — each entry of that filter answered alone over the paths
     *                    an arm compares, -p read beside it: a view's rows, a
     *                    range's two trees (scope_coverage_t: diff_validate_filter,
     *                    diff_commits).
     *   the predicates — the workspace arm's presentation (scope_accepts_path,
     *                    the profile asked with the path) and what its empty
     *                    line claims (scope_filters_profiles, scope_filters_paths).
     */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
        .paths         = opts->paths,
        .path_count    = opts->path_count,
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
enum diff_class { DIFF_CLASS_PATH = 1, DIFF_CLASS_GIT_REF, DIFF_CLASS_PROFILE, };

/**
 * Positional classifier for diff.
 *
 * Three-way split, each bucket claimed by a token that announces itself and the
 * last taking what announces nothing:
 *   - Looks like a ref → git_refs[] bucket (diff mode selector).
 *   - Announces a path → paths[] bucket (path filter).
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
    if (path_input_announces_path(tok)) return DIFF_CLASS_PATH;
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

    /* One stream, one direction: the two sections --all prints are the screen's,
     * refused in the engine's words (base/args.c apply_flag_set) */
    if (o->form == DIFF_FORM_RAW && o->direction == DIFF_BOTH) {
        return error_create(ERR_INVALID_ARG, "Option '--raw' contradicts '--all'");
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
    completion_files(ctx, out, o->profiles, o->profile_count);
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
    /* Two forms, each writing its enum into the same int, so giving both is the
     * engine's refusal (base/args.c apply_flag_set). Default (no flag): the field
     * stays 0, DIFF_FORM_PATCH. */
    ARGS_FLAG_SET(
        "name-only",
        cmd_diff_options_t,form,               DIFF_FORM_NAMES,
        "Print changed paths only"
    ),
    ARGS_FLAG_SET(
        "raw",
        cmd_diff_options_t,form,               DIFF_FORM_RAW,
        "Print only the patch, in git's format"
    ),
    /* Classified positionals: paths go to paths[], git refs to git_refs[],
     * everything else to profiles[]. The classify() function above decides. */
    ARGS_POSITIONAL(
        DIFF_CLASS_PATH,   cmd_diff_options_t, paths, path_count
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
    .usage        = "%s diff [options] [<commit>] [<commit>] [<path>...]",
    .description  =
        "Modes:\n"
        "  (no args)             Workspace diff (profile <-> filesystem).\n"
        "  <commit>              Commit -> workspace.\n"
        "  <commit> <commit>     Commit -> commit (must share a profile).\n"
        "  [<path>...]           Restrict any mode to the named paths.\n",
    .notes        =
        "Path Arguments:\n"
        "  A path holding *, ? or [ is also a pattern, and a \\ before each\n"
        "  names it alone. A leading ! leaves it out.\n"
        "\n"
        "Patches:\n"
        "  Compared with the file on disk, a patch shows an encrypted file's\n"
        "  plaintext; under --raw it names each file mode 100644 and by its\n"
        "  plaintext's hash. Between two commits, an encrypted file reads as\n"
        "  binary.\n",
    .examples     =
        "  %s diff                          # Preview apply (default)\n"
        "  %s diff --name-only              # Only changed paths\n"
        "  %s diff --raw --downstream       # Only the patch, for a pager\n"
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
