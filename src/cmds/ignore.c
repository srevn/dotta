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
#include "base/buffer.h"
#include "base/error.h"
#include "base/gitignore.h"
#include "base/heap.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "core/ignore.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "infra/label.h"
#include "infra/mount.h"
#include "infra/path.h"
#include "sys/editor.h"
#include "sys/filesystem.h"
#include "sys/gitops.h"
#include "sys/stage.h"

/**
 * Does any line of content name the same rule as pattern? (zero-allocation)
 *
 * Rules, not text: the lines are read from where the file's begin, past a
 * byte-order mark at its head (gitignore_file_lines), each as base/gitignore
 * reads it, and two lines are one rule iff their spans are equal byte for byte —
 * so `foo` and `foo   ` are one rule while `foo` and `  foo` are two, and a
 * blank or comment line names none. `span` is the pattern's own, which the caller
 * has already asked for — never zero, since ignore_post_parse refused every
 * argument that makes no rule. A span is the rule's identity, not its line: the
 * caller writes the pattern whole.
 *
 * Presence, not standing: a line a later `!` shadows is still held, so `--add
 * foo` over `foo` and then `!foo` adds nothing, and the rule stays shadowed.
 * The file is edited as lines; what its rules decide is the verdict's question.
 */
static bool ignore_holds(const char *content, const char *pattern, size_t span) {
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
 * Refuse a rule named by both --add and --remove, before the file is opened.
 *
 * The edit would write it and take it back — two receipts for a file that ends
 * as it began, or differs by a separator newline alone. Compared as rules, as
 * ignore_holds compares them: `--add foo --remove 'foo   '` names one rule.
 * Every span is nonzero here, since ignore_post_parse refused the rest first,
 * and the rule is quoted as written — its span, the spelling a verdict reports
 * it under.
 */
static error_t ignore_require_disjoint(
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
                return error_create(
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
 * Append each pattern whose rule the file does not hold, as a line of its own
 *
 * Written as given, with its newline — the line ignore_post_parse read it as,
 * so the file reads back the rule the pattern was checked as. The pattern, never
 * its span: `foo<CR><SP>` is the rule foo<CR>, and its span written back alone
 * would be the rule foo. Deduplication is by rule (ignore_holds), against the
 * file as it grows.
 *
 * `file` is the file as read, or the seed — never empty, since ignore_blob_text
 * answers an empty blob as absent and ignore_modify seeds the absent one — so
 * no pattern lands at the head of the file, where a byte-order mark in front of
 * it would be the file's and not the pattern's.
 *
 * @return How many were appended
 */
static size_t ignore_add(buffer_t *file, char **patterns, size_t count) {
    CHECK_NULL(file);

    /* Asking ignore_holds of the file as it grows answers both the file's own
     * rules and the batch's: a pattern appended earlier is in the file. */
    size_t added = 0;
    for (size_t i = 0; i < count; i++) {
        const char *p = patterns[i];
        size_t length = strlen(p);
        if (ignore_holds(file->data, p, gitignore_rule_span(p, length))) {
            continue;
        }

        /* A last line without its newline gains one before a pattern follows
         * it, so no pattern joins a line of the file's. */
        if (file->data[file->size - 1] != '\n') {
            buffer_append(file, "\n", 1);
        }
        buffer_append(file, p, length);
        buffer_append(file, "\n", 1);
        added++;
    }

    return added;
}

/**
 * Take out every line naming a rule a pattern names, counting the requests by rule
 *
 * A line goes where its span equals a request's, byte for byte, as ignore_holds
 * reads them; a blank or comment line names none and stays, and so do the bytes
 * before the first line (gitignore_file_lines), which are the file's. The kept
 * lines move down over the ones taken out, in place — removal only shrinks.
 * Requests are counted by rule, as --add counts them: two that name one rule —
 * `foo` and `foo   ` — are one request, removed or missing once.
 *
 * @return The requests a line named; `*missing` the rest
 */
static size_t ignore_remove(buffer_t *file, char **patterns, size_t count, size_t *missing) {
    CHECK_NULL(file);
    CHECK_NULL(missing);

    /* Each request's rule, its span asked once and read on every line; and whether
     * a line named it */
    size_t *spans = heap_calloc(count, sizeof(*spans));
    bool *found = heap_calloc(count, sizeof(*found));
    for (size_t i = 0; i < count; i++) {
        spans[i] = gitignore_rule_span(patterns[i], strlen(patterns[i]));
    }

    /* The lines begin where the grammar says, and the bytes before them — a
     * byte-order mark — are the file's: the kept lines are written from where
     * the first line begins, so removing the first rule never removes the mark,
     * nor makes the file's a mark the next line holds as pattern content. */
    const char *line = gitignore_file_lines(file->data);
    char *kept = file->data + (line - file->data);

    /* Line by line, zero-allocation: a line and its newline are one step, and
     * the last line needs no newline. What is kept is written behind the read,
     * never ahead of it. */
    while (*line) {
        size_t len = strcspn(line, "\n");
        size_t step = len + (line[len] == '\n');
        size_t span = gitignore_rule_span(line, len);

        /* The first request that names this line's rule, in the order given. A
         * blank or comment line's span is zero, which no request's is:
         * ignore_post_parse refused every argument that makes no rule. */
        size_t i;
        for (i = 0; i < count; i++) {
            if (spans[i] == span && memcmp(line, patterns[i], span) == 0) {
                break;
            }
        }

        if (i < count) {
            found[i] = true;
        } else {
            /* Not removed: kept as written (preserves original formatting) */
            memmove(kept, line, step);
            kept += step;
        }

        line += step;
    }
    buffer_resize(file, (size_t) (kept - file->data));

    /* Counted by rule, as --add counts: a request naming the rule of an earlier
     * one is that request again — the walk marked the earlier — and is neither
     * removed nor missing a second time. */
    size_t removed = 0;
    *missing = 0;
    for (size_t i = 0; i < count; i++) {
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
            removed++;
        } else {
            (*missing)++;
        }
    }

    free(spans);
    free(found);

    return removed;
}

/**
 * The .dottaignore an edit changes: the baseline at its own ref, or a named
 * profile's on its branch.
 *
 * Captures everything that differs between the two so ignore_edit and ignore_modify
 * stay ref-agnostic. Constructed on the stack in cmd_ignore; the profile's refname
 * lives in that frame too, its layer's words in the command arena.
 */
typedef struct {
    const char *refname;        /* BASELINE_REF or the profile's branch ref */
    const char *layer;          /* The layer, as the screens name it: "baseline" or "profile 'X'" */
    const char *seed;           /* What stands in where it has none: defaults or template */
} dottaignore_t;

/**
 * Edit a .dottaignore via external editor.
 *
 * Called with dottaignore->refname already verified to exist (cmd_ignore hoists
 * that check). Opens the ref's stage, hands the bytes its tree holds to the user's
 * editor, commits the edit on that stage, and says whether a commit was made.
 *
 * The bytes, not the text (ignore_blob_read): a human reads the file here, so a
 * .dottaignore every other reader refuses — one holding a NUL — opens as it stands,
 * to be mended. The write refuses what those readers would, and an edit the stage
 * refuses is kept, named in the refusal.
 */
static error_t ignore_edit(
    git_repository *repo,
    const dottaignore_t *dottaignore,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(dottaignore);

    /* The ref's stage, opened before the editor: the read the session decides
     * from is its tree, so a commit another writer makes to the ref while the
     * editor is open refuses this session's commit where it was overwritten
     * (sys/stage.h stage_commit); a deletion meanwhile is the stage's own rule,
     * the ref recreated with the edit */
    stage_t *stage = NULL;
    error_t err = stage_open(repo, dottaignore->refname, &stage);
    if (err) return err;

    buffer_t file = BUFFER_INIT;
    char *kept = NULL;
    char *commit_msg = NULL;

    /* The file's bytes, or its seed where it has none: what the editor opens
     * on, and one buffer from here to the write. */
    err = ignore_blob_read(repo, stage_tree(stage), dottaignore->refname, &file);
    if (err) goto cleanup;
    if (file.size == 0) {
        buffer_append_string(&file, dottaignore->seed);
    }

    /* The user's editor, in a file of the edit's own that stands after it
     * (sys/editor.h editor_edit) */
    err = editor_edit("dotta-ignore", &file, &kept);
    if (err) {
        err = error_wrap(err, "Failed to edit %s .dottaignore", dottaignore->layer);
        goto cleanup;
    }

    /* Whether anything changed is the stage's answer, asked of the tree the write
     * leaves: one equal to the ref's commits nothing — the editor closed on the
     * bytes the branch holds — and the receipt says which. An edit that leaves
     * a NUL is refused before it is staged, changed or not. */
    commit_msg = heap_str_format("Update %s .dottaignore", dottaignore->layer);
    bool committed = false;
    err = ignore_blob_write(stage, file.data, file.size);
    if (!err) err = stage_commit(stage, commit_msg, &committed);

    /* An edit the stage refused is kept where the editor left it, and the refusal
     * says where — a clause of the fact, which -q keeps; one the stage took lets
     * its file go. */
    if (err) {
        err = error_wrap(
            err, "Failed to update %s .dottaignore; the edit is kept in '%s'",
            dottaignore->layer, kept
        );
        goto cleanup;
    }
    unlink(kept);

    if (committed) {
        output_success(
            out, OUTPUT_NORMAL, "Updated %s .dottaignore", dottaignore->layer
        );
    } else {
        output_info(
            out, OUTPUT_NORMAL, "No changes to %s .dottaignore", dottaignore->layer
        );
    }

cleanup:
    free(kept);
    free(commit_msg);
    buffer_deinit(&file);
    stage_free(stage);
    return err;
}

/**
 * Add / remove patterns in a .dottaignore non-interactively.
 *
 * Called with dottaignore->refname already verified to exist. Opens the ref's
 * stage and loads the text its tree holds (ignore_blob_text) into one buffer,
 * which --add and --remove each change in place, each answering its count, and
 * commits it on that stage where a count says it changed: a line appended grows
 * the file and a line taken out shrinks it, so the stage is asked nothing the
 * counts have not said.
 */
static error_t ignore_modify(
    git_repository *repo,
    const dottaignore_t *dottaignore,
    char **add_patterns,
    size_t add_count,
    char **remove_patterns,
    size_t remove_count,
    output_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(dottaignore);

    /* The ref's stage, opened before the read: the patterns are matched against
     * the tree the commit lands on, and a commit another writer makes to the
     * ref meanwhile refuses this one (sys/stage.h stage_commit). Nothing the
     * user typed is lost to a refusal — the patterns are the command line, run
     * again. */
    stage_t *stage = NULL;
    error_t err = stage_open(repo, dottaignore->refname, &stage);
    if (err) return err;

    buffer_t text = BUFFER_INIT;
    char *commit_msg = NULL;

    err = ignore_blob_text(repo, stage_tree(stage), dottaignore->refname, &text);
    if (err) goto cleanup;

    /* Nothing to work with: no existing file and no adds to seed one. Wording
     * uses "%s .dottaignore" so it composes naturally for both layers: "No baseline
     * .dottaignore exists" / "No profile 'foo' .dottaignore exists". */
    if (text.size == 0 && add_count == 0) {
        output_info(
            out, OUTPUT_NORMAL, "No %s .dottaignore exists",
            dottaignore->layer
        );
        goto cleanup;
    }

    /* The file, or its seed where it has none — as the editor opens it — so the
     * adds have a file to land in. */
    if (text.size == 0) {
        buffer_append_string(&text, dottaignore->seed);
    }

    size_t added = ignore_add(&text, add_patterns, add_count);
    size_t missing = 0;
    size_t removed = ignore_remove(&text, remove_patterns, remove_count, &missing);

    /* Nothing actually changed — report why and stop. */
    if (added == 0 && removed == 0) {
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
        goto cleanup;
    }

    if (added > 0 && removed > 0) {
        commit_msg = heap_str_format(
            "Update %s .dottaignore (added %zu, removed %zu patterns)",
            dottaignore->layer, added, removed
        );
    } else if (added > 0) {
        commit_msg = heap_str_format(
            "Add %zu pattern%s to %s .dottaignore",
            added, added == 1 ? "" : "s", dottaignore->layer
        );
    } else {
        commit_msg = heap_str_format(
            "Remove %zu pattern%s from %s .dottaignore",
            removed, removed == 1 ? "" : "s", dottaignore->layer
        );
    }

    err = ignore_blob_write(stage, text.data, text.size);
    if (!err) err = stage_commit(stage, commit_msg, NULL);
    if (err) {
        err = error_wrap(err, "Failed to update %s .dottaignore", dottaignore->layer);
        goto cleanup;
    }

    if (added > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Added %zu pattern%s to %s .dottaignore",
            added, added == 1 ? "" : "s", dottaignore->layer
        );
    }
    if (removed > 0) {
        output_success(
            out, OUTPUT_NORMAL,
            "Removed %zu pattern%s from %s .dottaignore",
            removed, removed == 1 ? "" : "s", dottaignore->layer
        );
    }
    if (missing > 0) {
        output_info(
            out, OUTPUT_NORMAL,
            "Warning: %zu pattern%s not found (already removed or never added)",
            missing, missing == 1 ? "" : "s"
        );
    }

cleanup:
    free(commit_msg);
    buffer_deinit(&text);
    stage_free(stage);
    return err;
}

/**
 * The kind the rules are asked with: what stands where the argument stands, or
 * `hint` where nothing can be looked at.
 *
 * One lstat, the link itself and never its target — add's walk and the untracked
 * scan both classify this way and offer a symlink whole (cmds/add.c add_collect,
 * core/workspace.c workspace_scan), so a `pointer/` rule that does not decide
 * there must not decide here. A stat would follow the link, and a broken one
 * would read as absent; both are answers about something other than the path.
 *
 * `filesystem_path` is NULL for a custom/ name this asker binds no target for:
 * the name stands nowhere, so nothing can be looked at and the source tree has
 * no path to be asked about either. That, an absent path and an unreadable one
 * are one answer — the kind was not observed and `hint`, the argument's trailing
 * slash, stands in, which is what lets a rule be tested against a path that does
 * not exist yet — and each says which at VERBOSE, so a verdict that leaned on
 * the hint says so. An unreadable path is never reported as an absent one
 * (sys/filesystem.h: a reader must never infer absence from a failure to look).
 *
 * An observed leaf is a leaf whatever the hint says: `--test ~/foo/` where ~/foo
 * is a file is matched as a file.
 *
 * `who` names the asker whose reading this is, or is empty: a path is one reading
 * for every asker and is observed once, before the loop; a storage name stands
 * where each asker's own target puts it, and each says so in its own turn. `typed`
 * is the argument as the user wrote it — the only thing there is to name when
 * nothing stands anywhere for it to be.
 */
static path_kind_t ignore_kind(
    const char *who,
    const char *typed,
    const char *filesystem_path,
    path_kind_t hint,
    output_t *out
) {
    if (!filesystem_path) {
        output_info(
            out, OUTPUT_VERBOSE,
            "%s'%s' has no deployment target here: only the name is matched",
            who, typed
        );
        return hint;
    }

    switch (fs_lstat_occupant(filesystem_path, NULL)) {
        case FS_OCCUPANT_DIRECTORY:
            return PATH_KIND_DIRECTORY;

        case FS_OCCUPANT_REGULAR:
        case FS_OCCUPANT_SYMLINK:
        case FS_OCCUPANT_OTHER:
            return PATH_KIND_FILE;

        case FS_OCCUPANT_NONE:
            output_info(
                out, OUTPUT_VERBOSE, "%sPath does not exist: %s",
                who, filesystem_path
            );
            break;

        case FS_OCCUPANT_UNKNOWN:
            output_info(
                out, OUTPUT_VERBOSE, "%sPath cannot be read: %s",
                who, filesystem_path
            );
            break;
    }

    return hint;
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
 *     so the path, and the kind and source verdict that follow from it, are read
 *     once per asker. Nothing here names anything, so no view is built: a literal
 *     name stays testable on a repository whose claim sheets will not load.
 *   - a filesystem path (absolute, tilde, relative, a bare name) is one path
 *     for every asker — the machine's reading, asked once — and each asker names
 *     it from its own claims and its own roots (core/manifest.h manifest_name):
 *     a directory the profile already tracks names what lies beneath it, and
 *     only where nothing of the profile's stands above the path do its roots
 *     answer. That is the whole reason a view is built here.
 *   - a name with an empty tail (`home/`, `home`) is the namespace's own directory
 *     and is evaluated per asker like any name, on `""`, which no rule reaches.
 *
 * The *shape* is read by label_prefixes and not by the resolver, because a bare
 * name that is none of the three words is a filesystem argument here — `dotta
 * ignore --test foo.log` reads it against the working directory, as add's grammar
 * does — and path_input_resolve refuses one, its callers' first positional being
 * a profile. What the shape dispatches to *is* the resolver for a storage spelling,
 * which sheds the directory slash; the filesystem arm is the argument's reading
 * alone, whose answer is what the view's rows are keyed by too (infra/mount.h).
 * Both are read before the view is built, so a refusal is a plain return.
 *
 * The path need not exist: a trailing slash on one that does not is the directory
 * hint, so directory-only patterns (`cache/`) can be tested. The path meets the
 * ladder's one question, as the walk asks it (core/ignore.h ignore_verdict):
 * the rules on the asker's name for it, and, where no `.dottaignore` layer excludes
 * it, the source tree's on the path, when the asker places it.
 *
 * The view is the named profile's at HEAD — which need not be enabled, and answers
 * when some *other* enabled profile will not build — or the enabled set's. Neither
 * is declared: `ignore` is an editing command whose other four surfaces must
 * build nothing.
 *
 * Every asker gets a subject, so every turn casts a verdict: a name's own tail,
 * or the tail of the name the asker gives the path — `""` at a root of its own,
 * which no rule reaches (base/gitignore.c), so a root tests NOT IGNORED for every
 * asker and its entries are what a pattern can name.
 *
 * The verdicts are the answer, and no line sums them into a forecast: the rules
 * decide discovery (core/ignore.h, what the rules reach), and never reach a path
 * its profile holds. So where the argument is a path its asker holds, a verdict
 * that excludes it is followed by a note saying so; a storage name builds no
 * view to know, and says nothing. An asker whose Git's rules cannot be read for
 * the path could not tell, and says why — never NOT IGNORED, which what could
 * not be read may belie — and the note follows that answer too, which the rules
 * do not decide for a held path either.
 *
 * Cost: a filesystem argument pays a manifest build — a tree walk and a sheet
 * load per enabled profile — where it read the table alone. cmds/completion.c
 * already pays that on every tab press and records the measurement; a `--test`
 * invocation is not tighter than a completion. The other face of the same cost:
 * an enabled profile whose branch or sheet will not build refuses `--test` on a
 * filesystem argument, as it refuses status, apply and list. The named profile's
 * arm is insulated by construction, and a storage argument builds nothing.
 */
static error_t ignore_test(
    const dotta_ctx_t *ctx,
    const cmd_ignore_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);
    CHECK_NULL(opts->test_path);

    git_repository *repo = ctx->run.repo;
    const state_t *state = ctx->run.state;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* The directory hint is read from the argument as typed, and it is the only
     * thing read from it: both readings below shed a trailing slash of their
     * own — the resolver's storage arm sheds it, and str_path_fold folds it away
     * — so nothing here has to hand them a shortened copy. Shortening it *before*
     * the dispatch is what used to read `home/` as the working directory's `home`.
     * It is the kind the argument alone gives, which stands wherever nothing
     * can be looked at (ignore_kind). */
    size_t len = strlen(opts->test_path);
    const path_kind_t hint = len > 1 && opts->test_path[len - 1] == '/'
        ? PATH_KIND_DIRECTORY : PATH_KIND_FILE;

    /* The profile named must be here before anything is read under it: the view
     * below is its own, and the refusal names both ways out. */
    error_t err = opts->profile ? profile_require(repo, opts->profile) : NULL;
    if (err) return err;

    /* The key the user named, fixed for every asker: the resolver's sum, its
     * tag the whole condition the loop's arms read and its member the argument's
     * own reading. The table is the run's until a view is built, and then the
     * view's own — the one its rows were placed by. */
    const mount_table_t *mounts = ctx->run.mounts;
    path_input_t arg;                         /* the key: a name or a path */
    manifest_t *view = NULL;                  /* a path's: where each asker names it */

    if (label_prefixes(opts->test_path)) {
        /* A storage shape, read by the one resolver that reads input shapes — a
         * name and never a path, since the same predicate dispatched here
         * (cmds/add.c's storage head is the other). A bare name that is none of
         * the three words never arrives: that is this command's own filesystem
         * grammar, and the predicate above let it past. */
        err = path_input_resolve(opts->test_path, ctx->arena, &arg);
        if (err) return err;
    } else {
        /* The key as the argument's reading spells it: absolute, folded, nothing
         * read through — the resolver's own filesystem arm, read here because
         * the resolver refuses the bare name this grammar reads (infra/path.h
         * path_input_filesystem_path). */
        arg.key = PATH_KEY_FILESYSTEM;
        err = path_input_filesystem_path(opts->test_path, ctx->arena, &arg.filesystem_path);
        if (err) return err;
    }

    /* What each key owes before there is an asker to ask — the reading above,
     * and the two keys this command answers (infra/path.h). */
    switch (arg.key) {
        case PATH_KEY_STORAGE:
            /* The name is the one the rules read, for every asker alike. */
            break;

        case PATH_KEY_FILESYSTEM:
            /* Each asker names the path from its own claims and its own roots,
             * so a view is built and the table the rows were placed by is the
             * view's from here on — the named profile's arm hands in the very
             * table this lends back (core/manifest.h manifest_mounts). */
            if (opts->profile) {
                profile_t *profile = NULL;
                err = profile_load(repo, opts->profile, &profile);
                if (!err) err = manifest_build_profile(profile, mounts, ctx->arena, &view);
                profile_free(profile);
            } else {
                err = manifest_build(repo, state, ctx->arena, &view);
            }
            if (err) return err;

            mounts = manifest_mounts(view);
            break;
    }

    /* Layered-rules builder — the baseline compiled once, each profile's ruleset
     * composed on first request; no CLI layer, for --test takes no -e. The arena's,
     * and so is its source layer, so every directory and rule file it reads is
     * read once across the loop. */
    ignore_rules_t *ignore_rules = NULL;
    err = ignore_rules_create(repo, config, NULL, ctx->arena, &ignore_rules);
    if (err) return err;

    /* The askers: the profile named, the enabled set, or the one asker that is
     * no profile — which names through the shared roots and meets the baseline,
     * the config's layer and Git's rules. `askers` starts at the option itself,
     * an array of one that is both the named-profile and the nothing-enabled
     * case; the enabled set replaces it when it holds any, and so does what the
     * preamble keys on. */
    const char *const *askers = &opts->profile;
    size_t asker_count = 1;
    string_array_t enabled = { 0 };

    if (!opts->profile) {
        /* The enabled set, resolved for either key: a path's view, built over
         * the same rows a moment before, holds the same profiles unless a ref
         * moved between the two reads */
        err = scope_resolve_enabled(repo, state, ctx->arena, &enabled);
        if (err) return err;

        err = scope_require_enabled(state, &enabled, ctx->arena);
        if (err) {
            /* None to ask: said as a failure the run goes past, in the words
             * that say whether nothing is enabled or no enabled profile has its
             * branch — and dropped, so the loop meets no failure in hand. Then
             * the layers the one asker that is no profile meets, in the words
             * its verdict names them by: Git's where the builder opened them. */
            output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
            err = NULL;
            output_info(
                out, OUTPUT_NORMAL, "%s", ignore_source(ignore_rules)
                    ? "Testing against the baseline .dottaignore, config file patterns "
                "and Git's ignore rules"
                    : "Testing against the baseline .dottaignore and config file patterns"
            );
        } else {
            /* The set asked is the enabled profiles whose branch is here, and
             * the count says so: an enabled profile Git holds no branch for is
             * none of them */
            askers = (const char *const *) enabled.entries;
            asker_count = enabled.count;
            output_info(out, OUTPUT_NORMAL, "Testing path: %s", opts->test_path);
            output_info(
                out, OUTPUT_NORMAL, "Enabled profiles with a branch: %zu", asker_count
            );
            output_gap(out, OUTPUT_NORMAL);
        }
    }

    /* The kind the argument gives: a path's, one reading for every asker, so
     * one observation and no asker to name it — the loop reads it and asks nothing
     * of the path again; a name's, the hint, which each asker's look refines
     * where its target puts the name. Taken after the preamble rather than where
     * the key was read, so the note it may print stands under the same header
     * the per-asker notes of a storage name stand under — one command saying
     * one thing in one order. */
    const path_kind_t argument_kind = arg.key == PATH_KEY_FILESYSTEM
        ? ignore_kind("", opts->test_path, arg.filesystem_path, hint, out) : hint;

    for (size_t i = 0; i < asker_count; i++) {
        const char *asker = askers[i];

        /* Whose answer this is, on every line of the turn. One value, in the
         * command's arena, so each message below is spelled once and no site
         * can forget the form the asker that is no profile needs. */
        const char *who = asker ? arena_str_format(ctx->arena, "Profile '%s': ", asker) : "";

        /* The asker's reading of the key the user named: each arm keeps the half
         * the argument gave and fills the half it did not. */
        const char *name;
        const char *filesystem_path;
        path_kind_t kind;
        switch (arg.key) {
            case PATH_KEY_STORAGE:
                /* One name for every asker alike, standing where this asker's
                 * target puts it, and what stands there: a custom/ name places
                 * only under a profile with a target. */
                name = arg.storage_path;
                filesystem_path = mount_resolve(ctx->arena, mounts, asker, name);
                kind = ignore_kind(who, opts->test_path, filesystem_path, argument_kind, out);
                break;

            case PATH_KEY_FILESYSTEM:
                /* The machine's one reading and the kind observed there once,
                 * and what this asker calls the path: the claims it holds above
                 * it, else its own roots — the word alone at one of them, whose
                 * tail is "" and which no rule reaches. */
                name = manifest_name(ctx->arena, view, asker, arg.filesystem_path, NULL);
                filesystem_path = arg.filesystem_path;
                kind = argument_kind;
                break;
        }

        output_info(
            out, OUTPUT_VERBOSE, "%sMatching '%s' as '%s'%s", who, opts->test_path,
            label_tail(name), kind == PATH_KIND_DIRECTORY ? " (a directory)" : ""
        );

        const gitignore_ruleset_t *rules = NULL;
        err = ignore_ruleset(ignore_rules, asker, &rules);
        if (err) return err;

        /* The ladder's one question: the rules on the name, and where they exclude
         * nothing, the source tree's on the path — the lowest layer, so a `!`
         * above it re-opens its rung. Three answers, in the order of the header's
         * fates (core/ignore.h ignore_verdict). */
        ignore_verdict_t verdict;
        error_t failure = ignore_verdict(
            rules, ignore_source(ignore_rules), name, filesystem_path, kind, &verdict
        );
        if (failure) {
            /* Git's rules could not be read where the four exclude nothing: never
             * read as no exclusion, since what could not be read may be what
             * git excludes. The asker could not tell, and the failure's one line
             * says why (sys/source.h) — answered again for each asker it fails. */
            output_print(out, OUTPUT_NORMAL, "{yellow}?{reset} %sCOULD NOT TELL\n", who);
            output_info(out, OUTPUT_NORMAL, "  Reason: %s", error_line(failure));
        } else if (verdict.origin != IGNORE_ORIGIN_NONE) {
            output_print(out, OUTPUT_NORMAL, "{red}✗{reset} %sIGNORED\n", who);
            output_info(
                out, OUTPUT_NORMAL, "  Reason: %s", ignore_verdict_describe(ctx->arena, &verdict)
            );
        } else {
            output_success(out, OUTPUT_NORMAL, "%sNOT IGNORED", who);
            continue;
        }

        /* A path this asker holds is no discovery: the rules never reach it,
         * and only an -e leaves it out. Said beneath the verdicts that would
         * read otherwise, where a view names the path — a claim, never a directory
         * the asker only passes through. */
        const manifest_row_t *held = view
            ? manifest_lookup_claim(view, asker, filesystem_path) : NULL;
        if (held && !manifest_is_derived(held)) {
            output_info(
                out, OUTPUT_NORMAL,
                "  Profile '%s' holds it: these rules decide what is new, never what "
                "a profile holds", asker
            );
        }
    }

    return NULL;
}

/**
 * Main command implementation
 */
error_t cmd_ignore(const dotta_ctx_t *ctx, const cmd_ignore_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    /* The two modes that change no .dottaignore: the compiled defaults, printed
     * — a discoverability aid, the safety patterns read without grepping the
     * source or cloning the repo — and the ladder's verdict, which walks every
     * enabled profile by itself. */
    switch (opts->mode) {
        case IGNORE_MODE_DEFAULTS: {
            const char *defaults = ignore_baseline_defaults();
            output_write(out, OUTPUT_NORMAL, OUTPUT_COLOR_RESET, defaults, strlen(defaults));
            return NULL;
        }

        case IGNORE_MODE_TEST:
            return ignore_test(ctx, opts);

        case IGNORE_MODE_EDIT:
        case IGNORE_MODE_MODIFY:
            break;
    }

    /* The .dottaignore edit and modify change: the file's home, its layer on
     * the screen, and what an editor opens on when the file is not there yet.
     * Each arm establishes its home before naming it — the profile named must
     * be here, the baseline's ref must stand — so edit and modify start on a
     * ref that exists. The stage each opens would refuse a ref that is not there
     * as well, in the ref's own words; these say it in the user's, with the way
     * to bring it back. The profile's refname lives in this frame, its layer's
     * words in the command arena. */
    char refname[DOTTA_REFNAME_MAX];
    dottaignore_t dottaignore;
    if (opts->profile) {
        error_t err = profile_require(repo, opts->profile);
        if (err) return err;

        err = gitops_branch_refname(refname, sizeof(refname), opts->profile);
        if (err) return err;
        dottaignore = (dottaignore_t){
            .refname = refname,
            .layer = arena_str_format(ctx->arena, "profile '%s'", opts->profile),
            .seed = ignore_profile_template(),
        };
    } else {
        /* Seeded by `dotta init` and `dotta clone`; absent only by hand, and
         * init is what puts it back — on a repository that stands, which no fact
         * implies, so the clause says so. */
        bool seeded = false;
        error_t err = gitops_reference_exists(repo, BASELINE_REF, &seeded);
        if (err) return err;
        if (!seeded) {
            return error_create(
                ERR_NOT_FOUND, "No baseline .dottaignore: '%s' does not exist; dotta "
                "init seeds it with the default patterns", BASELINE_REF
            );
        }
        dottaignore = (dottaignore_t){
            .refname = BASELINE_REF,
            .layer = "baseline",
            .seed = ignore_baseline_defaults(),
        };
    }

    if (opts->mode == IGNORE_MODE_MODIFY) {
        return ignore_modify(
            repo, &dottaignore, opts->add_patterns, opts->add_count,
            opts->remove_patterns, opts->remove_count, out
        );
    }
    return ignore_edit(repo, &dottaignore, out);
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Settle the mode, one per run: --add and --remove make the edit one by rule,
 * and change the file together; --test and --list-defaults are modes of their
 * own. A flag that would make a second mode is refused before anything is read
 * — two things asked, and one would be done. The profile is no mode: it names
 * whose file an edit changes, or which asker --test asks, and beside
 * --list-defaults it changes nothing the defaults are.
 *
 * Then the edit's patterns, which the line alone decides: an argument that is
 * not one rule, and a rule both added and removed.
 */
static error_t ignore_post_parse(void *opts_v, arena_t *arena, const args_command_t *cmd) {
    (void) arena;
    (void) cmd;
    cmd_ignore_options_t *o = opts_v;

    /* Each flag refines the mode the ones before it left, and a refinement of
     * anything but the editor is a second mode. */
    o->mode = o->add_count > 0 || o->remove_count > 0 ? IGNORE_MODE_MODIFY : IGNORE_MODE_EDIT;
    if (o->test_path) {
        if (o->mode != IGNORE_MODE_EDIT) {
            return error_create(ERR_INVALID_ARG, "Cannot use --test with --add or --remove");
        }
        o->mode = IGNORE_MODE_TEST;
    }
    if (o->list_defaults) {
        if (o->mode != IGNORE_MODE_EDIT) {
            return error_create(
                ERR_INVALID_ARG, "Cannot use --list-defaults with --test, --add or --remove"
            );
        }
        o->mode = IGNORE_MODE_DEFAULTS;
    }

    /* An argument of the edit by rule is read as the line it would be in the
     * file: one that makes no rule, or two, is refused by name rather than written
     * (gitignore_validate_pattern). Only the edit by rule takes any. */
    for (size_t i = 0; i < o->add_count; i++) {
        error_t err = gitignore_validate_pattern(o->add_patterns[i]);
        if (err) {
            return error_wrap(err, "Invalid --add pattern");
        }
    }
    for (size_t i = 0; i < o->remove_count; i++) {
        error_t err = gitignore_validate_pattern(o->remove_patterns[i]);
        if (err) {
            return error_wrap(err, "Invalid --remove pattern");
        }
    }

    /* And a rule both added and removed, which the edit would write and take
     * back */
    return ignore_require_disjoint(
        o->add_patterns, o->add_count, o->remove_patterns, o->remove_count
    );
}

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

static error_t ignore_dispatch(const void *ctx_v, void *opts_v) {
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
    ARGS_FLAG_SET(
        "v verbose",
        cmd_ignore_options_t,verbosity,       DOTTA_VERBOSITY_VERBOSE,
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
        "Ignore Layers (highest precedence first):\n"
        "  1. CLI --exclude patterns (per operation)\n"
        "  2. Config file patterns ([ignore] patterns)\n"
        "  3. Profile .dottaignore (travels with the profile)\n"
        "  4. Baseline .dottaignore (this machine's)\n"
        "  5. Git's ignore rules, where the path stands (lowest precedence)\n"
        "\n"
        "Pattern Subject:\n"
        "  A pattern is matched against the path as seen from the directory\n"
        "  it deploys under, as a .gitignore at ~, at / or at the deployment\n"
        "  target would match it: write .config/Code/Cache/ for\n"
        "  ~/.config/Code/Cache, never ~/ or home/.\n"
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
    .post_parse  = ignore_post_parse,
    .complete    = ignore_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
        .mounts  = true,
    },
    .dispatch    = ignore_dispatch,
};
