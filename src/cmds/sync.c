/**
 * sync.c - The store meets its remote
 */

#include "cmds/sync.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/profiles.h"
#include "core/scope.h"
#include "core/state.h"
#include "infra/commit.h"
#include "infra/epoch.h"
#include "infra/label.h"
#include "sys/gitops.h"
#include "sys/remote.h"
#include "sys/transfer.h"
#include "utils/hooks.h"

#define LIST_LIMIT 20  /* Every capped list in this file trims here. */

/**
 * The act the run carries out on a row
 *
 * One verdict a row, read off its reading once (sync_verdict, at sync_decide)
 * and read by the preview, the act and the receipt: none decides again,
 * core/cleanup.h's stance. It is what the reading calls for, whatever the run's
 * words: --no-push skips a push's act whole and a merge's push after its commit,
 * at the act (sync_acts, sync_merge), and the printers say so. One mechanism a
 * verdict, written from the relation's read — a push the session's, one update
 * leased on the remote's head as the open listed it (sync_push); a pull, a deletion
 * and a create a write of the branch here, from its read (sys/gitops.h); a merge
 * the profile's own (sync_merge). Where two readings share one, its arm reads
 * the reading for its words: a push creating the remote's branch, a pull taking
 * a profile recreated there. The head a branch is created at is no arm's choice:
 * the relation names it (sys/remote.h remote_relation_t from).
 *
 * None is a row with nothing to carry out: the sides agree, or the row is kept
 * and said — commits this store holds beyond a line the remote deleted or
 * recreated, no branch here and none to come back from.
 */
typedef enum {
    SYNC_VERDICT_NONE,          /* Nothing to carry out */
    SYNC_VERDICT_PUSH,          /* The local commits onto the remote, or the branch it lacks */
    SYNC_VERDICT_PULL,          /* The remote's head onto the branch: its commits, or its line recreated */
    SYNC_VERDICT_MERGE,         /* Each side's commits: the profile's merge, then pushed */
    SYNC_VERDICT_DELETE,        /* The branch deleted here, as on the remote */
    SYNC_VERDICT_CREATE         /* The branch created here, where the relation says it comes back from */
} sync_verdict_t;

/**
 * What carrying a row's verdict out came to — read by the receipt
 * (sync_print_receipt) and the glyph its rows lead with (sync_print_lead), by
 * the run's summary (sync_print_summary) and the side a merge's conflicts keep
 * (sync_print_conflicts), and, through the row's error, by the run's failure
 * (sync_failure)
 *
 * One act moves the branch before a step that can fail after it: a merge, then
 * its push, the merge standing where it was committed — the branch ahead of the
 * remote, the next sync's push. Every other act is one write, which lands or
 * moves nothing. Nothing is rolled back.
 */
typedef enum {
    SYNC_OUTCOME_NONE,          /* Not carried out: no act, a push --no-push skips, a row its decision refused */
    SYNC_OUTCOME_DONE,          /* The act carried out whole */
    SYNC_OUTCOME_FAILED,        /* The act failed, nothing moved: its cause the row's error */
    SYNC_OUTCOME_UNPUSHED       /* A merge committed here, then its push failed: the branch ahead */
} sync_outcome_t;

/**
 * A name both sides of a merge took since their merge base, one deleting it and
 * the other removing it (sync_disagreements)
 */
typedef struct {
    const char *storage_path;            /* The name, as the profile's tree holds it */
    profile_departure_t remote;          /* The remote's, DELETED or REMOVED: the local side's the other */
} sync_disagreement_t;

/** The disagreements one merge met — a value of the command arena */
typedef struct {
    const sync_disagreement_t *entries;
    size_t count;
} sync_disagreements_t;

/**
 * A row of the run: its branch against the remote, what the run decided, what
 * the act did
 *
 * Each column is written once, by its phase: the decision the relation, the verdict
 * and of a merge its draft and the conflicts its open met — refusing it, or each
 * settled for the run's side; the act the outcome, what its push sent, and of a
 * merge that landed the names its two sides took one deleting and one removing.
 * The row's error is the failure the run met for it, whichever phase met it —
 * said on the row's line, counted and named by sync_failure. A row whose relation
 * failed has no verdict, and every reader asks its error before its reading: a
 * failed relation's zeroed state reads as up to date otherwise.
 */
typedef struct {
    const char *profile;                 /* The run's name, borrowed */
    remote_relation_t relation;          /* Its branch against the remote: the heads every act writes from */
    sync_verdict_t verdict;              /* The act the reading calls for */
    profile_draft_t *draft;              /* A merge's, opened at the decision, committed at the act; NULL elsewhere */
    profile_conflicts_t conflicts;       /* A merge's open's, refusing it or settled; none elsewhere */
    sync_outcome_t outcome;              /* What carrying the verdict out came to */
    transfer_wire_t sent;                /* What the act sent: its push's, none where no push landed */
    sync_disagreements_t disagreements;  /* A merge's that landed; none elsewhere */
    error_t error;                       /* The failure's cause, borrowed; NULL where the run met none */
} sync_row_t;

/** The rows: one per profile of the run, in its order — a value of the command arena */
typedef struct {
    sync_row_t *entries;
    size_t count;
} sync_rows_t;

/**
 * A profile's departed files, by their departures at the head the acts left
 * (sync_departure_counts): the Manifest line's three words for what left
 */
typedef struct {
    size_t removed;     /* REMOVED, NEVER_HELD, GONE: no deletion committed */
    size_t deleted;     /* DELETED: update's removals took it */
    size_t unverified;  /* UNVERIFIED */
} sync_departure_counts_t;

/**
 * Print what an op moved, the last part of the line that says the op — the fetch's,
 * the epoch's establish and adopt, a row's act: dim, at verbose, the wire's phrase
 * (sys/transfer.h transfer_wire_phrase) in parentheses, and nothing where nothing
 * moved
 */
static void sync_print_wire(output_t *out, transfer_wire_t wire) {
    if (wire.objects == 0) return;

    char phrase[TRANSFER_PHRASE_MAX];
    transfer_wire_phrase(wire, phrase, sizeof(phrase));
    output_print(out, OUTPUT_VERBOSE, " {dim}(%s){reset}", phrase);
}

/**
 * What a reading calls for (sys/remote.h remote_state_t): the act read off the
 * reading alone, as cleanup_verdict reads an orphan's off the item
 *
 * The branch here follows the remote where the remote's answer is an absence or
 * a history of its own and the branch holds nothing beyond what the remote's
 * line held: deleted where the remote deleted it, the remote's taken where it
 * recreated it. Everywhere else nothing this store took is let go: a remote moved
 * back is pushed forward again, a branch gone here created back — at the head
 * this store kept, where it holds commits the remote lacks — a line both sides
 * moved merged, and commits beyond a line the remote deleted or recreated kept
 * and said, with their ways out (sync_print_remedies).
 */
static sync_verdict_t sync_verdict(remote_state_t state) {
    switch (state) {
        case REMOTE_STATE_UP_TO_DATE:         return SYNC_VERDICT_NONE;
        case REMOTE_STATE_AHEAD:              return SYNC_VERDICT_PUSH;
        case REMOTE_STATE_BEHIND:             return SYNC_VERDICT_PULL;
        case REMOTE_STATE_DIVERGED:           return SYNC_VERDICT_MERGE;
        case REMOTE_STATE_RECREATED:          return SYNC_VERDICT_PULL;
        case REMOTE_STATE_RECREATED_AHEAD:    return SYNC_VERDICT_NONE;
        case REMOTE_STATE_NO_REMOTE:          return SYNC_VERDICT_PUSH;
        case REMOTE_STATE_DELETED:            return SYNC_VERDICT_DELETE;
        case REMOTE_STATE_DELETED_AHEAD:      return SYNC_VERDICT_NONE;
        case REMOTE_STATE_NO_LOCAL:           return SYNC_VERDICT_CREATE;
        case REMOTE_STATE_NO_LOCAL_AHEAD:     return SYNC_VERDICT_CREATE;
        case REMOTE_STATE_NO_LOCAL_DELETED:   return SYNC_VERDICT_NONE;
        case REMOTE_STATE_NO_LOCAL_NO_REMOTE: return SYNC_VERDICT_NONE;
    }

    CHECK_ARG(false, "a remote state no enumerator names");
}

/**
 * Whether the run carries a row's act out: a row its decision did not refuse,
 * whose reading calls for an act, and not a push --no-push skips — asked where
 * the act is carried out (sync_execute) and where the preview says it will be
 * (sync_print_preview), so the preview promises what the act does
 */
static bool sync_acts(const sync_row_t *row, bool no_push) {
    return !row->error && row->verdict != SYNC_VERDICT_NONE &&
           !(no_push && row->verdict == SYNC_VERDICT_PUSH);
}

/**
 * Decide the run whole, before any row acts: a row a profile of `profiles`, in
 * its order, each read against the remote three ways (sys/remote.h
 * remote_relation), given the act its reading calls for (sync_verdict), and of
 * a merge the draft opened — each conflict settled for --conflicts' side, or
 * the open refused naming each where the run named none (core/profiles.h
 * profile_draft_merge) — so a conflict refuses its row before anything moves,
 * in a dry run too
 *
 * A relation that fails is its row's error, which no verdict reads; an open that
 * fails is its row's too. The open hands its conflicts back where it succeeds
 * and where they refuse it, and nowhere else, in the command arena the receipt
 * reads them from: a merge whose conflicts stand listed with no draft is their
 * refusal, said as the row's own off the list, each conflict beneath it — the
 * row naming its profile, as the push's compare is said (sync_push) — and every
 * other refusal of the open stands whole. The open reads the branch's head itself
 * (sys/stage.h stage_merge), moments after the relation read it: a commit another
 * process lands between the two is merged with the rest, and the push is refused
 * where that process pushed (stated).
 *
 * @param ctx Dispatch context: the store, and the command arena the rows and
 *            their conflicts live in (must not be NULL)
 * @param remote The session, its fetch run (must not be NULL)
 * @param profiles The run's profiles, in its order (must not be NULL; borrowed)
 * @param opts Command options: --conflicts' side (must not be NULL)
 * @return The rows, each merge's draft its own (released by profile_draft_free)
 */
static sync_rows_t sync_decide(
    const dotta_ctx_t *ctx, const remote_t *remote, const string_array_t *profiles,
    const cmd_sync_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(remote);
    CHECK_NULL(profiles);
    CHECK_NULL(opts);

    sync_rows_t rows = {
        .entries = arena_calloc(ctx->arena, profiles->count, sizeof(*rows.entries)),
        .count   = profiles->count,
    };

    for (size_t i = 0; i < rows.count; i++) {
        sync_row_t *row = &rows.entries[i];

        row->profile = profiles->entries[i];
        row->error = remote_relation(remote, row->profile, &row->relation);
        if (row->error) continue;

        row->verdict = sync_verdict(row->relation.state);
        if (row->verdict != SYNC_VERDICT_MERGE) continue;

        row->error = profile_draft_merge(
            ctx->run.repo, row->profile, &row->relation.remote, opts->conflicts_side,
            ctx->arena, &row->conflicts, &row->draft
        );
        if (row->conflicts.count > 0 && !row->draft) {
            row->error = error_create(
                ERR_CONFLICT, "The merge met %zu conflict%s", row->conflicts.count,
                row->conflicts.count == 1 ? "" : "s"
            );
        }
    }

    return rows;
}

/**
 * Push a row's branch: `target` onto the remote's, leased on the remote's head
 * as the open listed it — Git's null id where the remote held none, a create —
 * so the push lands only over the remote this sync read (sys/remote.h remote_push);
 * what it sent is the row's
 *
 * Every push the run makes: a push's the branch's head the relation read, a merge's
 * its commit. The compare's refusal, which the push's header gives that one cause,
 * is said as the row's own, the row naming its profile and the title the remote,
 * as remove says its lease's (cmds/remove.c remove_moved); every other refusal
 * is the push's, the remote's words where it refused the ref.
 */
static error_t sync_push(remote_t *remote, sync_row_t *row, const git_oid *target) {
    char ref[DOTTA_REFNAME_MAX];
    error_t err = gitops_branch_refname(ref, sizeof(ref), row->profile);
    if (err) return err;

    err = remote_push(remote, ref, target, &row->relation.remote, &row->sent);
    if (error_code(err) == ERR_CONFLICT) {
        return error_create(ERR_CONFLICT, "The remote's branch moved since this sync read it");
    }
    return err;
}

/**
 * The names both sides of a merge took since their merge base, one deleting each
 * and the other removing it
 *
 * The local side's deletions first: every name the profile claimed at the merge
 * base that the tree diff from it to the local head deletes — a blob retyped is
 * a deletion there beside an addition — and the departures read each for what
 * it is: the base holds each name, so the local side's history answers it from
 * the local side's own commits. Where the local side took none, no history is
 * read. Then the remote's history is asked of them (core/profiles.h
 * profile_departures): a name it holds the local side took alone, the common
 * case, which costs that one walk, mostly the remote head's own descent. Only
 * the names it says the remote took, DELETED or REMOVED, are asked of the local
 * side's history, and each the local side took under the other word is a
 * disagreement. The two heads are the merge's parents, its caller's to hand —
 * never the remote-tracking ref read again, which a push moves past the remote's
 * head.
 *
 * The merge itself is asked nothing: both its parents lack each such name, so
 * its history follows each line to its removal (sys/history.h), and the one naming
 * no update keeps the name's copies on every machine (core/profiles.h
 * profile_departure_t) — the line's last word, whatever either side did.
 *
 * A history that will not say is no line (stated): no merge base, a tree or a
 * commit that will not load, a side whose walk went unread. Its error is dropped,
 * one a merge at most (base/error.h "Lifetime"), and so is the shape's refusal
 * of a malformed name under a label, one a name.
 *
 * @param arena The command arena, the answer's (must not be NULL)
 * @param repo Repository (must not be NULL)
 * @param local_oid The merge's first parent: the branch's head it was made on
 *                  (must not be NULL)
 * @param remote_oid Its second: the remote's head it integrated (must not be NULL)
 * @return The disagreements, none where the history says none
 */
static sync_disagreements_t sync_disagreements(
    arena_t *arena, git_repository *repo, const git_oid *local_oid,
    const git_oid *remote_oid
) {
    sync_disagreements_t found = { 0 };
    arena_t *frame = arena_create(0);
    git_tree *base_tree = NULL;
    git_tree *local_tree = NULL;
    git_diff *diff = NULL;

    /* The local side's deletions since the merge base, by one tree diff: the
     * names point into it, which lives until the end */
    git_oid base;
    error_t err = gitops_find_merge_base(repo, local_oid, remote_oid, &base);
    if (err || git_oid_is_zero(&base)) goto done;
    err = gitops_get_tree_from_commit(repo, &base, &base_tree);
    if (!err) err = gitops_get_tree_from_commit(repo, local_oid, &local_tree);
    if (!err) err = gitops_diff_trees(repo, base_tree, local_tree, NULL, &diff);
    if (err) goto done;

    /* A diff's names are Git's, so each deletion is read as the profile's walk
     * reads an entry (core/profiles.c profile_step), its gates in the walk's
     * order: what passes is a name the profile claimed at the base */
    const size_t delta_count = git_diff_num_deltas(diff);
    const char **names = arena_calloc(frame, delta_count, sizeof(*names));
    size_t name_count = 0;
    for (size_t i = 0; i < delta_count; i++) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (delta->status != GIT_DELTA_DELETED) continue;

        /* Machinery stands under no label: passed in silence, and before the
         * shape rule, so it is never read as corruption */
        const char *name = delta->old_file.path;
        if (!label_prefixes(name)) continue;

        /* A gitlink claims nothing, so the base never held its name, and the
         * local side's history would answer from below the base. The mode is
         * the tree's spelling, read as libgit2 reads an entry's
         * (lib/libgit2/src/libgit2/tree.c git_tree_entry_type: S_ISGITLINK) */
        if ((delta->old_file.mode & S_IFMT) == GIT_FILEMODE_COMMIT) continue;

        /* A name a hand's tree spells under a label outside the shape is
         * corruption, no profile's name: its error dropped, one a name */
        if (label_validate_storage(name)) continue;

        names[name_count++] = name;
    }
    if (name_count == 0) goto done;

    /* The remote's history first, and the names it says the remote took kept,
     * in place, each beside its departure */
    profile_departure_t *remote = arena_calloc(frame, name_count, sizeof(*remote));
    profile_departures(repo, remote_oid, names, name_count, remote);

    size_t taken = 0;
    for (size_t i = 0; i < name_count; i++) {
        if (remote[i].kind == PROFILE_DEPARTURE_DELETED ||
            remote[i].kind == PROFILE_DEPARTURE_REMOVED) {
            names[taken] = names[i];
            remote[taken] = remote[i];
            taken++;
        }
    }
    if (taken == 0) goto done;

    /* The local side's history, of those alone */
    profile_departure_t *local = arena_calloc(frame, taken, sizeof(*local));
    profile_departures(repo, local_oid, names, taken, local);

    /* A name the local side took under the other word of the two: the remote's
     * is one of them, so the local's is the other where it is either and differs */
    sync_disagreement_t *entries = arena_calloc(arena, taken, sizeof(*entries));
    size_t entry_count = 0;
    for (size_t i = 0; i < taken; i++) {
        if ((local[i].kind == PROFILE_DEPARTURE_DELETED ||
            local[i].kind == PROFILE_DEPARTURE_REMOVED) && local[i].kind != remote[i].kind) {
            entries[entry_count++] = (sync_disagreement_t){
                .storage_path = arena_strdup(arena, names[i]),
                .remote = remote[i],
            };
        }
    }
    found = (sync_disagreements_t){ .entries = entries, .count = entry_count };

done:
    git_diff_free(diff);
    git_tree_free(local_tree);
    git_tree_free(base_tree);
    arena_free(frame);

    return found;
}

/**
 * Carry a merge out: the draft the decision opened, committed, the remote's head
 * taken, then pushed unless --no-push skips it
 *
 * The commit is written only from the head the open read (core/profiles.h
 * profile_commit), so one another writer moved since refuses it, said in its
 * own words, and nothing moved. Committed, the merge stands: its history is read
 * once more, for the names its two sides took one deleting and one removing;
 * its tracking ref takes the remote's head, the line the merge took (sys/remote.h
 * remote_take); and a push that fails after it leaves the branch ahead of the
 * remote, the next sync's push. Nothing is rolled back and nothing verified:
 * the merge has the two heads as its parents by construction. So its outcome is
 * its own, the one act whose failure can follow a branch it moved.
 */
static void sync_merge(
    const dotta_ctx_t *ctx, remote_t *remote, const char *remote_name,
    sync_row_t *row, const cmd_sync_options_t *opts
) {
    /* Its commit, Git's line for a merge its whole message */
    const char *message = arena_str_format(
        ctx->arena, "Merge remote-tracking branch '%s/%s'",
        remote_name, row->profile
    );
    const commit_words_t words = {
        .action     = COMMIT_ACTION_SYNC,
        .custom_msg = message,
    };
    git_oid merge;
    row->error = profile_commit(row->draft, &words, &merge, NULL);
    if (row->error) {
        row->outcome = SYNC_OUTCOME_FAILED;
        return;
    }

    /* The names its two sides took, read off the merge itself — the head the
     * open read is its first parent, the remote's head its second — whether its
     * push lands or not */
    git_commit *commit = NULL;
    if (git_commit_lookup(&commit, ctx->run.repo, &merge) == 0) {
        row->disagreements = sync_disagreements(
            ctx->arena, ctx->run.repo,
            git_commit_parent_id(commit, 0), &row->relation.remote
        );
    }
    git_commit_free(commit);

    /* The remote's line, taken */
    remote_take(remote, row->profile);

    if (!opts->no_push) {
        row->error = sync_push(remote, row, &merge);
        if (row->error) {
            row->outcome = SYNC_OUTCOME_UNPUSHED;
            return;
        }
    }
    row->outcome = SYNC_OUTCOME_DONE;
}

/**
 * Carry every act out, in the run's order, printing nothing of its own: what
 * each came to, the failure it met and what it sent, written on its row for the
 * receipt
 *
 * Git only: a push moves the remote's branch, every other act a branch here — a
 * merge's commit reading its history once more, for its row's disagreements
 * (sync_merge) — and what the acts did to the view is read off once, for every
 * enabled profile, in the Manifest block (sync_print_manifest). Each verdict is
 * one mechanism, written from the relation's read and called as the decision
 * named it: nothing here decides again, and a row the run does not act on is
 * passed over, its outcome none (sync_acts). An act that wrote the branch here
 * off the remote — a pull, a merge's commit, a create — takes the remote's head
 * into its tracking ref after its own write landed, never before (sys/remote.h
 * remote_take): one refused leaves the ref on the line this store last took,
 * for the next sync to read as this one did. A push says the remote's words as
 * it runs, above the receipt as git's stand above its ref list — where it failed,
 * and under -v every push's as they come (sys/transfer.h
 * transfer_push_sideband_callback).
 */
static void sync_execute(
    const dotta_ctx_t *ctx, remote_t *remote, const char *remote_name,
    sync_rows_t *rows, const cmd_sync_options_t *opts
) {
    CHECK_NULL(ctx);
    CHECK_NULL(remote);
    CHECK_NULL(remote_name);
    CHECK_NULL(rows);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    const char *action = commit_action_word(COMMIT_ACTION_SYNC);

    for (size_t i = 0; i < rows->count; i++) {
        sync_row_t *row = &rows->entries[i];
        const remote_relation_t *relation = &row->relation;
        if (!sync_acts(row, opts->no_push)) continue;

        /* What the act sent is its push's, written where one landed (sync_push):
         * every other act moves a branch here and sends nothing */
        switch (row->verdict) {
            case SYNC_VERDICT_NONE:
                continue;  /* No act: passed over above */

            case SYNC_VERDICT_PUSH:
                /* The branch's head the relation read onto the remote's, or the
                 * branch where the remote held none */
                row->error = sync_push(remote, row, &relation->local);
                break;

            case SYNC_VERDICT_PULL: {
                /* The remote's head onto the branch, from the head the relation
                 * read — its commits, or the line it recreated, the branch holding
                 * nothing beyond the old one — then the remote's line taken */
                char ref[DOTTA_REFNAME_MAX];
                row->error = gitops_branch_refname(ref, sizeof(ref), row->profile);
                if (!row->error) {
                    row->error = gitops_write_reference(
                        repo, ref, &relation->remote, &relation->local, action, "%s %s/%s",
                        relation->state == REMOTE_STATE_RECREATED
                            ? "recreated from" : "fast-forward to", remote_name, row->profile
                    );
                }
                if (!row->error) remote_take(remote, row->profile);
                break;
            }

            case SYNC_VERDICT_MERGE:
                /* Its outcome its own: a push that fails after the commit leaves
                 * the merge standing (sync_merge) */
                sync_merge(ctx, remote, remote_name, row, opts);
                continue;

            case SYNC_VERDICT_DELETE:
                /* The branch deleted from the head the relation read, as on the
                 * remote; its tracking ref kept, the line its return reads against
                 * (sys/remote.h remote_relation_t) */
                row->error = gitops_delete_branch(repo, row->profile, &relation->local);
                break;

            case SYNC_VERDICT_CREATE:
                /* The branch created where the relation says it comes back from,
                 * its name free here, then the remote's line taken */
                row->error = gitops_create_branch(
                    repo, row->profile, &relation->from, action, "created from %s/%s",
                    remote_name, row->profile
                );
                if (!row->error) remote_take(remote, row->profile);
                break;
        }

        /* An act of one write came to it: carried out whole, or failed with nothing
         * moved */
        row->outcome = row->error ? SYNC_OUTCOME_FAILED : SYNC_OUTCOME_DONE;
    }
}

/**
 * Print a row's lead: its glyph, then its profile — the words every row of the
 * table sets before its clause
 *
 * The glyph is read off the row alone, alike in both tenses: ✗ where the row
 * holds an error — exactly the rows the run's failure counts (sync_failure) — ✓
 * where an act was carried out whole, and otherwise its reading's, in the colour
 * status's rows give the same reading (sys/remote.h remote_state_symbol,
 * remote_state_color). The glyph alone carries the row's colour; the profile is
 * cyan, as every screen spells one.
 */
static void sync_print_lead(output_t *out, const sync_row_t *row) {
    if (row->error) {
        output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "  ✗");
    } else if (row->outcome == SYNC_OUTCOME_DONE) {
        output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN, "  ✓");
    } else {
        output_colored(
            out, OUTPUT_NORMAL, remote_state_color(row->relation.state), "  %s",
            remote_state_symbol(row->relation.state)
        );
    }
    output_print(out, OUTPUT_NORMAL, " {cyan}%s{reset}: ", row->profile);
}

/**
 * Print where a row no act moved stands, alike in both tenses: its reading's
 * phrase (sys/remote.h remote_state_phrase), and beside a push --no-push skipped
 * the word that kept it; or the failure the run met for it
 *
 * The clause of a row nothing moves, in the preview and the receipt alike, so
 * the two tenses cannot drift — a row --no-push kept from its push, one its
 * decision refused, and in the receipt one whose act failed among them.
 */
static void sync_print_state(output_t *out, const sync_row_t *row, bool no_push) {
    if (row->error) {
        output_print(out, OUTPUT_NORMAL, "%s", error_line(row->error));
        return;
    }

    char phrase[REMOTE_PHRASE_MAX];
    remote_state_phrase(&row->relation, phrase, sizeof(phrase));
    output_print(out, OUTPUT_NORMAL, "%s", phrase);
    if (no_push && row->verdict == SYNC_VERDICT_PUSH) {
        output_print(out, OUTPUT_NORMAL, ", push skipped (--no-push)");
    }
}

/**
 * Print what a row's act will do: the receipt's act in the future tense
 * (sync_print_done), of a row the run acts on (sync_acts)
 */
static void sync_print_will(output_t *out, const sync_row_t *row, bool no_push) {
    const remote_relation_t *relation = &row->relation;

    switch (row->verdict) {
        case SYNC_VERDICT_NONE:
            break;  /* No act: the row says where it stands (sync_print_state) */

        case SYNC_VERDICT_PUSH:
            if (relation->state == REMOTE_STATE_NO_REMOTE) {
                output_print(out, OUTPUT_NORMAL, "will create remote branch");
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "will push %zu commit%s",
                    relation->ahead, relation->ahead == 1 ? "" : "s"
                );
            }
            break;

        case SYNC_VERDICT_PULL:
            if (relation->state == REMOTE_STATE_RECREATED) {
                output_print(out, OUTPUT_NORMAL, "will pull the recreated branch");
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "will pull %zu commit%s",
                    relation->behind, relation->behind == 1 ? "" : "s"
                );
            }
            break;

        case SYNC_VERDICT_MERGE:
            output_print(
                out, OUTPUT_NORMAL, "will merge the remote, %s",
                no_push ? "push skipped (--no-push)" : "then push"
            );
            break;

        case SYNC_VERDICT_DELETE:
            output_print(out, OUTPUT_NORMAL, "will delete it locally, as on the remote");
            break;

        case SYNC_VERDICT_CREATE:
            output_print(out, OUTPUT_NORMAL, "will create local branch");
            if (relation->ahead > 0) {
                output_print(
                    out, OUTPUT_NORMAL, ", %zu commit%s ahead",
                    relation->ahead, relation->ahead == 1 ? "" : "s"
                );
            }
            break;
    }
}

/**
 * Print what a row's act did: the preview's act in the past tense
 * (sync_print_will), of an act that moved the branch — carried out whole, or a
 * merge whose push failed after it, said where the merge stands, then the push's
 * cause
 */
static void sync_print_done(output_t *out, const sync_row_t *row, bool no_push) {
    const remote_relation_t *relation = &row->relation;

    switch (row->verdict) {
        case SYNC_VERDICT_NONE:
            break;  /* No act: the row says where it stands (sync_print_state) */

        case SYNC_VERDICT_PUSH:
            if (relation->state == REMOTE_STATE_NO_REMOTE) {
                output_print(out, OUTPUT_NORMAL, "created remote branch");
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "pushed %zu commit%s",
                    relation->ahead, relation->ahead == 1 ? "" : "s"
                );
            }
            break;

        case SYNC_VERDICT_PULL:
            if (relation->state == REMOTE_STATE_RECREATED) {
                output_print(out, OUTPUT_NORMAL, "pulled the recreated branch");
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "pulled %zu commit%s",
                    relation->behind, relation->behind == 1 ? "" : "s"
                );
            }
            break;

        case SYNC_VERDICT_MERGE:
            /* The merge stands where it was committed, so the act comes first,
             * then what came of its push */
            if (row->outcome == SYNC_OUTCOME_UNPUSHED) {
                output_print(
                    out, OUTPUT_NORMAL, "merged the remote, unpushed: %s",
                    error_line(row->error)
                );
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "merged the remote, %s",
                    no_push ? "push skipped (--no-push)" : "then pushed"
                );
            }
            break;

        case SYNC_VERDICT_DELETE:
            output_print(out, OUTPUT_NORMAL, "deleted locally, as on the remote");
            break;

        case SYNC_VERDICT_CREATE:
            output_print(out, OUTPUT_NORMAL, "created local branch");
            if (relation->ahead > 0) {
                output_print(
                    out, OUTPUT_NORMAL, ", %zu commit%s ahead",
                    relation->ahead, relation->ahead == 1 ? "" : "s"
                );
            }
            break;
    }
}

/**
 * Print, beneath a merge's row, each name its two sides took one deleting and
 * one removing: what this side and the remote did, the remote's removal, and
 * that the merge keeps the name's copies — it holds both removals, and the one
 * naming no update keeps them on every machine (sync_disagreements) — LIST_LIMIT
 * lines, and a count of the rest
 */
static void sync_print_disagreements(output_t *out, const sync_row_t *row) {
    const sync_disagreements_t *disagreements = &row->disagreements;

    for (size_t i = 0; i < disagreements->count && i < LIST_LIMIT; i++) {
        const sync_disagreement_t *disagreement = &disagreements->entries[i];

        /* The removal abbreviated, as every screen spells a commit */
        char oid_str[8];
        git_oid_tostr(oid_str, sizeof(oid_str), &disagreement->remote.removal);

        output_print(
            out, OUTPUT_NORMAL, "    %s: %s in %s — kept\n", disagreement->storage_path,
            disagreement->remote.kind == PROFILE_DEPARTURE_DELETED
                ? "removed locally, deleted" : "deleted locally, removed",
            oid_str
        );
    }
    if (disagreements->count > LIST_LIMIT) {
        output_print(
            out, OUTPUT_NORMAL, "    ... and %zu more\n", disagreements->count - LIST_LIMIT
        );
    }
}

/**
 * Print one side's value on a conflict's axis: a mode as %04o, an ownership as
 * chown(1) spells it — owner, owner:group or :group, as show spells one
 * (cmds/show.c show_print_blob) — and none where the side's claim names nothing
 * on the axis, absence being a value on each, as the merge reads it
 * (core/metadata.h metadata_merge_axis)
 */
static void sync_print_value(
    output_t *out, profile_axis_t axis, const profile_claim_t *claim
) {
    if (axis == PROFILE_AXIS_MODE && claim->mode != MODE_UNCLAIMED) {
        output_print(out, OUTPUT_NORMAL, "%04o", (unsigned) claim->mode);
    } else if (axis == PROFILE_AXIS_OWNERSHIP && (claim->owner || claim->group)) {
        output_print(
            out, OUTPUT_NORMAL, "%s%s%s", claim->owner ? claim->owner : "",
            claim->group ? ":" : "", claim->group ? claim->group : ""
        );
    } else {
        output_print(out, OUTPUT_NORMAL, "none");
    }
}

/**
 * The noun one side's entry at a content conflict reads as: what its tree holds
 * at the name, in the words every screen gives a node — a file, a symlink or a
 * directory, as path_type_noun names a claim's type, and a submodule, as show
 * names a gitlink (cmds/show.c show_file) — and none where it holds nothing,
 * absence being a value on the content as on a claim's axis (sync_print_value)
 */
static const char *sync_entry_noun(const profile_held_t *entry) {
    switch (entry->kind) {
        case PROFILE_HELD_NOTHING:
            return "none";
        case PROFILE_HELD_FILE:
            /* A link by its filemode; an executable is a file, its bit the claim's
             * mode */
            return entry->filemode == GIT_FILEMODE_LINK ? "symlink" : "file";
        case PROFILE_HELD_DIRECTORY:
            return "directory";
        case PROFILE_HELD_SUBMODULE:
            return "submodule";
    }

    CHECK_ARG(false, "a held kind no enumerator names");
}

/**
 * Print, beneath a merge's row, each conflict its open met: the name, and what
 * both sides moved apart there — the content, each side's entry named where the
 * two differ in what they are, or a claim's mode or ownership with each side's
 * value — then, where the open settled it, the run's side it keeps; LIST_LIMIT
 * lines, and a count of the rest
 *
 * The open's list, in its order (core/profiles.h profile_draft_merge): the same
 * conflicts whether the open refused naming each, the run having named no side,
 * or settled each for the side the run named (`side`), in a dry run's preview
 * as in the receipt. A merge whose commit failed after a settled open landed no
 * side's value, so its lines name the conflicts alone, as a refusal's do.
 */
static void sync_print_conflicts(
    output_t *out, const sync_row_t *row, profile_side_t side
) {
    const profile_conflicts_t *conflicts = &row->conflicts;

    for (size_t i = 0; i < conflicts->count && i < LIST_LIMIT; i++) {
        const profile_conflict_t *conflict = &conflicts->entries[i];

        /* The content is Git's refusal at the name, each side's entry named where
         * the two differ in what they are — a deletion beside an edit, a file
         * beside a directory or a link — and the name alone where both hold one
         * kind, their bytes apart; a claim's axis is said with both sides' values,
         * a directory's name with its slash */
        if (conflict->axis == PROFILE_AXIS_CONTENT) {
            const char *ours = sync_entry_noun(&conflict->entry_ours);
            const char *theirs = sync_entry_noun(&conflict->entry_theirs);
            if (strcmp(ours, theirs) == 0) {
                output_print(
                    out, OUTPUT_NORMAL, "    %s (content)",
                    conflict->storage_path
                );
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "    %s (content: %s ours, %s theirs)",
                    conflict->storage_path, ours, theirs
                );
            }
        } else {
            output_print(
                out, OUTPUT_NORMAL, "    %s%s (%s: ", conflict->storage_path,
                path_kind_suffix(path_type_kind(conflict->claim_ours->type)),
                conflict->axis == PROFILE_AXIS_MODE ? "mode" : "ownership"
            );
            sync_print_value(out, conflict->axis, conflict->claim_ours);
            output_print(out, OUTPUT_NORMAL, " ours, ");
            sync_print_value(out, conflict->axis, conflict->claim_theirs);
            output_print(out, OUTPUT_NORMAL, " theirs)");
        }

        /* An open that settled each for the run's side — its draft standing —
         * keeps that side where its merge has not failed since: a preview's, or
         * one that landed, pushed or not */
        if (row->draft && row->outcome != SYNC_OUTCOME_FAILED) {
            output_print(
                out, OUTPUT_NORMAL, " — %s kept",
                side == PROFILE_SIDE_OURS ? "ours" : "theirs"
            );
        }
        output_endline(out, OUTPUT_NORMAL);
    }
    if (conflicts->count > LIST_LIMIT) {
        output_print(
            out, OUTPUT_NORMAL, "    ... and %zu more\n",
            conflicts->count - LIST_LIMIT
        );
    }
}

/**
 * Print the preview: what the run will do, row by row in the run's order, titled
 * by the remote — a dry run's block
 *
 * The receipt's sibling (sync_print_receipt), in the future tense, each row in
 * the line both print: its lead, then what its act will do (sync_print_will),
 * or, for a row the run does not act on (sync_acts), where it stands, as the
 * receipt says it (sync_print_state); and beneath a merge's, each conflict its
 * open met, refusing it or with the side it keeps (sync_print_conflicts).
 */
static void sync_print_preview(
    output_t *out, const char *remote_name, const sync_rows_t *rows,
    bool no_push, profile_side_t side
) {
    output_section(out, OUTPUT_NORMAL, "Sync preview for '{cyan}%s{reset}'", remote_name);

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        sync_print_lead(out, row);
        if (sync_acts(row, no_push)) {
            sync_print_will(out, row, no_push);
        } else {
            sync_print_state(out, row, no_push);
        }
        output_endline(out, OUTPUT_NORMAL);
        sync_print_conflicts(out, row, side);
    }
}

/**
 * Print the receipt: what each act came to, row by row in the run's order, titled
 * by the remote, once every act is done
 *
 * The preview's sibling (sync_print_preview), in the past tense, each row in
 * the line both print — its lead, then its clause — and at verbose what its act
 * sent (sync_print_wire). An act that moved the branch is said in the preview's
 * words (sync_print_done), a merge whose push failed after it among them; a row
 * nothing moved, where it stands, as the preview says it (sync_print_state) —
 * one whose act failed by its cause. Beneath a merge that landed, pushed or not,
 * the names its two sides took one deleting and one removing
 * (sync_print_disagreements); and beneath a merge each conflict its open met,
 * refusing it or kept for `side`, the run's (sync_print_conflicts).
 */
static void sync_print_receipt(
    output_t *out, const char *remote_name, const sync_rows_t *rows,
    bool no_push, profile_side_t side
) {
    output_section(out, OUTPUT_NORMAL, "Sync with '{cyan}%s{reset}'", remote_name);

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        sync_print_lead(out, row);
        switch (row->outcome) {
            case SYNC_OUTCOME_NONE:
            /* No act, a push --no-push kept, or a row its decision refused */
            case SYNC_OUTCOME_FAILED:
                /* Or an act that failed: nothing moved it */
                sync_print_state(out, row, no_push);
                break;

            case SYNC_OUTCOME_DONE:
            /* The act carried out whole */
            case SYNC_OUTCOME_UNPUSHED:
                /* Or a merge whose push failed after it: the branch moved */
                sync_print_done(out, row, no_push);
                break;
        }
        sync_print_wire(out, row->sent);
        output_endline(out, OUTPUT_NORMAL);
        sync_print_disagreements(out, row);
        sync_print_conflicts(out, row, side);
    }
}

/**
 * A view of the run's own, built over the rows as they stand: NULL where the
 * build fails, its failure warned
 *
 * A failed build is not sync's failure — every Git ref an act moved stands —
 * and its message carries the repair (a tree that will not load, metadata that
 * will not parse): warned, the Manifest block skipped, and the run carried on,
 * so a pulled profile the build refuses is no reason the pull that brings its
 * repair cannot run. A pulled custom/ claim this machine cannot place does not
 * fail the build, nor does a pulled claim the profile's own tree contradicts:
 * the health sections after the block are their signal (cmd_sync).
 */
static manifest_t *sync_view(const dotta_ctx_t *ctx) {
    manifest_t *view = NULL;
    error_t err = manifest_build(ctx->run.repo, ctx->run.state, ctx->arena, &view);
    if (err) {
        output_gap(ctx->out, OUTPUT_NORMAL);
        output_warning(ctx->out, OUTPUT_NORMAL, "%s", error_line(err));
    }
    return view;
}

/**
 * Count a profile's departed files by their departures
 *
 * The rows the diff handed back as departed (core/manifest.h
 * manifest_diff_stats_t), their files asked of the profile's history in one walk
 * (core/profiles.h profile_departures), at the head the view after read
 * (core/manifest.h manifest_head): the branch as the acts left it, one read of
 * the ref for the view and the count alike — NULL where the branch is gone, a
 * deletion learned among them, which answers every name GONE. Every departure
 * that keeps counts removed: a removal under any action but update, or under
 * none; no commit that held the name; the branch gone. A directory is asked
 * nothing: a tracked one is a sheet item, never a blob, so no history says what
 * took it, and what is left in it decides its copy (v2sc) — and where no file
 * left, no history is read. A name the head holds counts nowhere: it left the
 * view and not the profile (stated).
 *
 * @param repo Repository (must not be NULL)
 * @param after The view after the acts, its heads the ones asked (must not be NULL)
 * @param stats One profile's slot of the diff (must not be NULL)
 * @return The counts, zero where no file departed
 */
static sync_departure_counts_t sync_departure_counts(
    git_repository *repo, const manifest_t *after, const manifest_diff_stats_t *stats
) {
    sync_departure_counts_t counts = { 0 };
    if (stats->departed.count == 0) return counts;

    /* The departed files' names, beside their answers, in a frame of the count's
     * own */
    arena_t *frame = arena_create(0);
    const char **paths = arena_calloc(frame, stats->departed.count, sizeof(*paths));
    size_t path_count = 0;
    for (size_t i = 0; i < stats->departed.count; i++) {
        const manifest_row_t *row = stats->departed.entries[i];
        if (path_type_kind(row->type) == PATH_KIND_FILE) {
            paths[path_count++] = row->storage_path;
        }
    }

    profile_departure_t *departures = arena_calloc(frame, path_count, sizeof(*departures));
    profile_departures(
        repo, manifest_head(after, stats->profile), paths, path_count, departures
    );

    for (size_t i = 0; i < path_count; i++) {
        switch (departures[i].kind) {
            case PROFILE_DEPARTURE_DELETED:
                counts.deleted++;
                break;

            case PROFILE_DEPARTURE_REMOVED:
            case PROFILE_DEPARTURE_NEVER_HELD:
            case PROFILE_DEPARTURE_GONE:
                counts.removed++;
                break;

            case PROFILE_DEPARTURE_UNVERIFIED:
                counts.unverified++;
                break;

            case PROFILE_DEPARTURE_HELD:
                break;
        }
    }

    arena_free(frame);
    return counts;
}

/**
 * Print the Manifest block: the view after the acts, diffed against the view
 * before them, a line for each profile they moved
 *
 * A true delta: a local external commit that predates the sync is in `before`
 * and `after` alike and is reported by its results (status's [stale], [released]),
 * not here; what the block names is what the acts did to the view. Sync writes
 * no state.
 *
 * Attribution is per enabled row — `enabled`, never the run the line narrowed:
 * precedence runs across the whole enabled set, which is what both views are
 * built over (the state's rows as the dispatch read them: nothing in sync writes
 * enabled_profiles or takes the lock that reads them again, so a profile change
 * another process commits meanwhile reaches neither view). A profile whose branch
 * a view lacks contributes nothing to it: one the run created back is all added,
 * one it deleted all departed, and one gone from both is said by status's and
 * apply's health off the view (core/manifest.h manifest_missing). A path p lost
 * to q is p's reassignment and q's claim; a path that moved between two pulled
 * profiles is one reassignment, never a claim departed beside one added; and a
 * claim of p's that a blob the pull brought now stands above is p's overridden,
 * never departed either: its copy is that blob's landing's, which clears it.
 *
 * Sync does not deploy, nor settle what an act let go: apply's divergence analysis
 * does both. The record is read for the diff, which hands back a departed claim
 * only where a record stands at its path (core/manifest.h manifest_diff); a read
 * that fails is warned and the block skipped, as a view that will not build is
 * (sync_view).
 *
 * @param ctx Dispatch context: the store, the state, the command arena and the
 *            output (must not be NULL)
 * @param enabled Every enabled row's name, in precedence order (must not be NULL)
 * @param before The view before the acts (must not be NULL)
 * @param after The view after them (must not be NULL)
 */
static void sync_print_manifest(
    const dotta_ctx_t *ctx, const string_array_t *enabled, const manifest_t *before,
    const manifest_t *after
) {
    output_t *out = ctx->out;

    state_record_t *records = NULL;
    size_t record_count = 0;
    error_t err = state_records(ctx->run.state, ctx->arena, &records, &record_count);
    if (err) {
        output_gap(out, OUTPUT_NORMAL);
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
        return;
    }

    manifest_diff_stats_t *stats = arena_calloc(ctx->arena, enabled->count, sizeof(*stats));
    manifest_diff(before, after, records, record_count, enabled, ctx->arena, stats);

    bool manifest_changed = false;  /* The block's header, said at its first line */
    for (size_t i = 0; i < enabled->count; i++) {
        const sync_departure_counts_t departed = sync_departure_counts(
            ctx->run.repo, after, &stats[i]
        );

        /* One line per profile, its non-zero counts in the diff's order: what
         * the acts added and updated, what passed to another profile, what
         * another's blob stands over, and what left, each file by its departure
         * at the head the acts left. A departure says what took the file, never
         * what becomes of its copy, which is the orphan analysis's
         * (core/workspace.c workspace_analyze_orphans), and the two part (stated):
         * an observed copy counts deleted, and the gate releases it; a reassigned
         * record's copy goes by its own profile's history, the line by the row's;
         * a copy already gone is reclaimed; and dotta's node above a row the
         * view after stands, or a copy beneath a blob it stands, is that row's
         * or that blob's landing's. A claim that left with no record asks nothing
         * of apply and is not counted. The line says what its table holds, so
         * one whose every count is zero — a directory that left, a name its profile
         * holds still — is no line. */
        const struct {
            size_t count;
            const char *word;
        } parts[] = {
            { stats[i].added,      "added"      },
            { stats[i].updated,    "updated"    },
            { stats[i].reassigned, "reassigned" },
            { stats[i].overridden, "overridden" },
            { departed.removed,    "removed"    },
            { departed.deleted,    "deleted"    },
            { departed.unverified, "unverified" },
        };

        size_t total = 0;
        for (size_t k = 0; k < sizeof(parts) / sizeof(parts[0]); k++) {
            total += parts[k].count;
        }
        if (total == 0) continue;

        if (!manifest_changed) {
            output_section(out, OUTPUT_NORMAL, "Manifest");
            manifest_changed = true;
        }

        output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset}:", stats[i].profile);
        const char *sep = " ";
        for (size_t k = 0; k < sizeof(parts) / sizeof(parts[0]); k++) {
            if (parts[k].count == 0) continue;

            output_print(
                out, OUTPUT_NORMAL, "%s%zu %s", sep, parts[k].count, parts[k].word
            );
            sep = ", ";
        }
        output_endline(out, OUTPUT_NORMAL);
    }
}

/**
 * Print the run's summary: how many profiles an act carried out whole, or where
 * none did, whether there was anything to sync
 *
 * Read off the rows the receipt printed, beneath it and what it did to the view.
 * A row is up to date where its lead says so (sync_print_lead): its reading.
 * Nothing to sync is said only where every row is, so the line never claims there
 * was no work where --no-push withheld it, the run keeps a row and says why, or
 * a failure kept it: there, nothing was synced.
 */
static void sync_print_summary(
    output_t *out, const char *remote_name, const sync_rows_t *rows
) {
    size_t synced = 0;
    size_t up_to_date = 0;
    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (row->outcome == SYNC_OUTCOME_DONE) {
            synced++;
        } else if (!row->error && row->relation.state == REMOTE_STATE_UP_TO_DATE) {
            up_to_date++;
        }
    }

    if (synced > 0) {
        output_success(
            out, OUTPUT_NORMAL, "Synced %zu profile%s with '{cyan}%s{reset}'",
            synced, synced == 1 ? "" : "s", remote_name
        );
    } else if (up_to_date == rows->count) {
        output_summary(out, OUTPUT_NORMAL, "Nothing to sync");
    } else {
        output_summary(out, OUTPUT_NORMAL, "Nothing was synced");
    }
}

/**
 * Print the remedies the rows call for, beneath the run's summary in both tenses:
 * one hint a family, said once however many rows call for it
 *
 * Five families. A merge its conflicts refused — its conflicts listed, and no
 * draft (sync_decide) — whose hint names --conflicts' two words, a re-run keeping
 * whatever else the run's line said. Then each reading the run keeps and says
 * (sync_verdict), its ways out, the remote's name the run's: commits beyond a
 * line the remote deleted — deleted here too, published again, or kept under
 * another name, the one way left where the remote holds a profile beneath the
 * name and refuses its push; commits beyond a line it recreated — kept under
 * another name, the next sync taking the remote's; no branch here, the remote's
 * deleted — dropped, or the line this store last took published again; no branch
 * on either side — dropped.
 */
static void sync_print_remedies(
    output_t *out, const char *remote_name, const sync_rows_t *rows
) {
    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (row->conflicts.count > 0 && !row->draft) {
            output_gap(out, OUTPUT_NORMAL);
            output_hint(
                out, OUTPUT_NORMAL, "Re-run this sync with --conflicts ours or "
                "--conflicts theirs to keep that side of every conflict"
            );
            break;
        }
    }

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (!row->error && row->relation.state == REMOTE_STATE_DELETED_AHEAD) {
            output_gap(out, OUTPUT_NORMAL);
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta remove <profile> --delete-profile' to delete "
                "a profile locally as the remote did, 'dotta git push %s <profile>' to "
                "publish it again, or 'dotta git branch -m <profile> <new-name>' to keep "
                "its commits under another name", remote_name
            );
            break;
        }
    }

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (!row->error && row->relation.state == REMOTE_STATE_RECREATED_AHEAD) {
            output_gap(out, OUTPUT_NORMAL);
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta git branch -m <profile> <new-name>' to keep "
                "the local commits of a profile the remote recreated under another name; "
                "the next sync then takes the remote's"
            );
            break;
        }
    }

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (!row->error && row->relation.state == REMOTE_STATE_NO_LOCAL_DELETED) {
            output_gap(out, OUTPUT_NORMAL);
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile disable <profile>' to drop a "
                "profile the remote deleted, or 'dotta git push %s refs/remotes/%s/<profile>"
                ":refs/heads/<profile>' to publish it again as this machine last fetched it",
                remote_name, remote_name
            );
            break;
        }
    }

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (!row->error && row->relation.state == REMOTE_STATE_NO_LOCAL_NO_REMOTE) {
            output_gap(out, OUTPUT_NORMAL);
            output_hint(
                out, OUTPUT_NORMAL, "Run 'dotta profile disable <profile>' to drop a "
                "profile with no branch locally or on the remote"
            );
            break;
        }
    }
}

/**
 * The run's failure, if it had one — the answer cmd_sync returns.
 *
 * A profile the run tried to reconcile and could not (a row with an error —
 * whatever the phase: the relation, a merge's open, or the act: a push, a pull,
 * a merge, a deletion, a create) is a broken promise, and only the return value
 * carries that to the caller. The reason was printed on the profile's own row —
 * on stdout, so a redirected sync's report never reads as a clean success — but
 * a shell reads none of it.
 *
 * A profile the run deliberately left alone is not a failure: the caller's word
 * withheld its push (--no-push), or the run keeps it and says why — commits beyond
 * a line the remote deleted or recreated, no branch on either side. Its own row
 * is its whole report, its remedy beneath the summary, and `dotta sync && dotta
 * apply` keeps working.
 *
 * Pure, and deliberately so: the per-profile errors stay in the rows that borrow
 * them and are never rethrown, since each was already said where it happened.
 * The message carries what no row says — how much of the run the failures were
 * — and names their profiles in the run's order: the one line a configured quiet,
 * which says no row, reads which failed by, a row's cause running on past its
 * line (base/output.h OUTPUT_QUIET).
 */
static error_t sync_failure(arena_t *arena, const sync_rows_t *rows) {
    string_array_t failed;
    string_array_init(&failed, arena, 0);
    for (size_t i = 0; i < rows->count; i++) {
        if (rows->entries[i].error) {
            string_array_push(&failed, rows->entries[i].profile);
        }
    }

    if (failed.count == 0) return NULL;

    /* The plural agrees with the total, which is the noun it qualifies: "1 of 2
     * profiles failed", "1 of 1 profile failed". The names are joined in the
     * arena the caller lent. */
    return error_create(
        ERR_GIT, "%zu of %zu profile%s failed to sync (%s)",
        failed.count, rows->count,
        rows->count == 1 ? "" : "s",
        string_array_join(arena, &failed, ", ")
    );
}

/**
 * Print one of the two refusals: the local epoch reads, differs from the remote's
 * canonical epoch, and keys reachable ciphertext (head or history, any branch).
 * Two independent encryption roots, and every hint below is licensed by the census
 * having attributed a blob to the one that stands here. Warn loudly and continue
 * — plaintext profiles still sync.
 */
static void sync_print_epoch_conflict(output_t *out) {
    output_gap(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL,
        "Repository epoch conflict: the local epoch differs from the remote's; "
        "encrypted files pulled by this sync will not decrypt"
    );
    output_hint(
        out, OUTPUT_NORMAL,
        "Re-clone if this machine's encrypted files came from the remote; "
        "otherwise reconcile the independent encryption roots manually"
    );
    output_hint(
        out, OUTPUT_NORMAL,
        "Or delete the profiles whose encrypted content (including history) "
        "you no longer need ('dotta remove <name> --delete-profile'); the "
        "next sync then adopts the remote epoch"
    );
}

/**
 * Print the other: the local ref stands, yields no epoch, and this repository
 * holds encrypted files that may be sealed under the bytes it carries. A different
 * finding from the conflict and so a different remedy — none of that one's three
 * remedies fit a ref that is merely unreadable, where the salt blob is often
 * intact and one fetch away from whole. This is `epoch_init`'s refusal over the
 * identical state, said by the other verb. The fetch is the epoch's own restore
 * refspec (epoch.h), forced and naming the one ref, from the remote this sync
 * reached, on the condition the refspec's comment states.
 *
 * Reached with encryption on or off: sync declares no crypto, so its dispatch
 * reads no epoch, where a command that reads ciphertext is refused over a ref
 * that yields none (main.c open_run), naming the same restore with no remote to
 * name.
 */
static void sync_print_epoch_damaged(output_t *out, const char *remote_name) {
    output_gap(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL,
        "Repository epoch left alone: '%s' cannot be read and this repository "
        "holds encrypted files that may be sealed under it", EPOCH_REF
    );
    output_hint(
        out, OUTPUT_NORMAL,
        "If '%s' holds this repository's epoch, restore the ref rather than "
        "replacing it: dotta git fetch %s '" EPOCH_RESTORE_REFSPEC "'",
        remote_name, remote_name
    );
}

/**
 * Apply the CLI gates to epoch_resolve's verdict, print the outcome, and run
 * the chosen git action (establish by the session's push, adopt by epoch_adopt
 * over the objects the run's one fetch brought). The fact-finding already happened
 * in infra/epoch; this layer is pure policy and printing.
 *
 * Runs after the fetch and before any profile acts: its verdict reads the open's
 * listing (sys/remote.h remote_advertised), and its census walks the local branches
 * (infra/epoch.c epoch_walk), which a pull moves and the fetch does not. Every
 * outcome is best-effort — a warning and the rest of the sync — which is why
 * nothing here is returned: the two errors the resolve produces, a local ref
 * that would not read and a census that could not finish, are verdicts to print,
 * not a run to fail.
 *
 * The epoch is machinery, so it says as little as it can get away with. Four of
 * the six verdicts are a verbose line or nothing at all: dotta either did the
 * right thing or had nothing to do, and neither is the user's business at NORMAL.
 * What speaks up is what the user has to act on — a divergence over ciphertext,
 * a ref that cannot be read over ciphertext, and a resolve that could not decide
 * — and each is one line of finding plus one of remedy or cause. Nothing here
 * reports the census, the salt, or which of three routes reached an adopt.
 */
static void sync_reconcile_epoch(
    const dotta_ctx_t *ctx,
    remote_t *remote,
    const char *remote_name,
    const cmd_sync_options_t *opts
) {
    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;

    epoch_decision_t decision;
    error_t err = epoch_resolve(repo, remote, &decision);
    if (err) {
        /* No decision: the local ref would not read, or the census could not
         * finish — each error says which, in its own words (infra/epoch.h
         * epoch_resolve) — so no absence was proved and the verdict is the one
         * a found ciphertext gets: no git op. Sync is the only place either is
         * ever reported, so the line says what it knows and the error the rest. */
        output_gap(out, OUTPUT_NORMAL);
        output_warning(
            out, OUTPUT_NORMAL, "Repository epoch left alone: %s", error_line(err)
        );
        return;
    }

    /* The outcome is a block of its own at the level it speaks at: a verbose
     * line, under the one boundary asked here for every arm, or a warning or a
     * printer, each asking its own. At normal no verbose debt is owed, so a silent
     * outcome leaves the report as it found it. */
    output_gap(out, OUTPUT_VERBOSE);
    switch (decision.verdict) {
        case EPOCH_RECONCILE_EQUAL:
            output_info(out, OUTPUT_VERBOSE, "Repository epoch up to date");
            return;

        case EPOCH_RECONCILE_NO_LOCAL_EPOCH:
            /* Nothing to publish; never claim an establish (the guard). "Usable"
             * covers both ways the ref fails to yield an epoch, and 'dotta init'
             * is the right remedy for each — it repairs one that binds nothing
             * and refuses one that may. */
            output_info(
                out, OUTPUT_VERBOSE,
                "No usable local repository epoch to establish (run 'dotta init')"
            );
            return;

        case EPOCH_RECONCILE_ESTABLISH: {
            /* Establish is push-shaped: gate on --no-push. */
            if (opts->no_push) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Remote has no repository epoch; establish skipped"
                );
                return;
            }
            if (opts->dry_run) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Would establish repository epoch on remote"
                );
                return;
            }

            /* The local epoch's commit, the one the verdict judged, pushed where
             * the remote held none: a create, so `dotta init` → `dotta remote
             * add` → `dotta sync` ships the epoch with no hand's push, before
             * any profile's. Two machines that minted their own and race to one
             * remote meet here — the second's push finds the first's epoch in
             * its own listing and is refused, changed by another writer, and
             * its next sync reconciles the two. The failure names its act, the
             * ref and the remote, then the cause (sys/remote.h remote_push):
             * printed whole, beneath the remote's words where it sent any
             * (sys/transfer.h transfer_op_end) */
            transfer_wire_t sent = { 0 };
            err = remote_push(remote, EPOCH_REF, &decision.local, &decision.advertised, &sent);
            if (err) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
                return;  /* best-effort; retried next sync */
            }
            output_print(
                out, OUTPUT_VERBOSE,
                "{green}✓{reset} Established repository epoch on remote"
            );
            sync_print_wire(out, sent);
            output_endline(out, OUTPUT_VERBOSE);
            return;
        }

        case EPOCH_RECONCILE_CONFLICT:
            sync_print_epoch_conflict(out);
            return;  /* warn-and-continue; no git op */

        case EPOCH_RECONCILE_DAMAGED:
            sync_print_epoch_damaged(out, remote_name);
            return;  /* warn-and-continue; no git op */

        case EPOCH_RECONCILE_ADOPT: {
            /* Three findings, one act (epoch.h): whatever stands at the local
             * ref — nothing, unreadable bytes, or an epoch that keys nothing
             * here — is not worth keeping, so the remote's replaces it. One line
             * for all three, and it describes the act rather than the census
             * that licensed it: only one of the three ran a census it could
             * attribute, so any "no local ciphertext depended on it" would be a
             * claim about work that did not happen on the other two. */
            if (opts->dry_run) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Would adopt repository epoch from remote"
                );
                return;
            }

            /* The objects are the fetch's, which named the epoch and said what
             * it moved: the adopt moves nothing on the wire. Every failure names
             * its act and leaves the local ref standing — one it could not adopt
             * was judged before it was installed — so each is printed whole, as
             * clone prints it */
            err = epoch_adopt(repo, &decision, remote_name, COMMIT_ACTION_SYNC);
            if (err) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
                return;  /* best-effort */
            }
            output_print(
                out, OUTPUT_VERBOSE,
                "{green}✓{reset} Adopted repository epoch from remote"
            );
            output_endline(out, OUTPUT_VERBOSE);

            /* What the old epoch's session file holds is not this run's to remove:
             * the file is named by the epoch, and a checkout still on that epoch
             * is the one entitled to read it (crypto/session.h). */
            return;
        }
    }
}

/**
 * Sync command implementation
 */
error_t cmd_sync(const dotta_ctx_t *ctx, const cmd_sync_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources, initialized to NULL. */
    error_t err = NULL;
    sync_rows_t rows = { 0 };                  /* The run's rows, each merge's draft their own */
    const char *remote_name = NULL;
    remote_t *remote = NULL;                   /* The remote, met once */

    /* The enabled rows, each a profile whether its branch is here or not
     * (core/state.h state_profiles), in precedence order: the set the line's
     * names are checked against, and the Manifest block's attribution. Nothing
     * in sync writes them or takes the lock that reads them again, so they stand
     * for the run. */
    const state_profiles_t enabled_rows = state_profiles(state);
    string_array_t enabled_profiles;
    string_array_init(&enabled_profiles, ctx->arena, enabled_rows.count);
    for (size_t i = 0; i < enabled_rows.count; i++) {
        string_array_push(&enabled_profiles, enabled_rows.entries[i].name);
    }

    /* The run's profiles: every enabled row the line names, each checked against
     * the rows (core/scope.h scope_filter), or every one where it names none —
     * a branch here or none, for a branchless row comes back from the remote */
    string_array_t filter;
    err = scope_filter(
        repo, &enabled_profiles, opts->profiles, opts->profile_count, ctx->arena, &filter
    );
    if (err) goto cleanup;
    const string_array_t *profiles = filter.count > 0 ? &filter : &enabled_profiles;

    /* Nothing to sync: refused, in the words that say nothing is enabled — a
     * row whose branch is gone is in the run */
    err = scope_require_enabled(state, &enabled_profiles, ctx->arena);
    if (err) goto cleanup;

    /* Which remote, early — fail fast, before the hook and the network; its URL
     * is the open's to read (sys/remote.h remote_default) */
    err = remote_default(repo, ctx->arena, &remote_name);
    if (err) goto cleanup;

    /* Build the hook invocation. Same struct is reused for both pre-sync (here)
     * and post-sync (after the manifest block). The invocation's strings are
     * the command arena's; sync_extras is a stack literal whose lifetime is
     * cmd_sync's frame — covers both fire sites. */
    char *const sync_extras[] = {
        arena_str_format(ctx->arena, "DOTTA_REMOTE=%s", remote_name), NULL
    };
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_SYNC,
        .profile    = string_array_join(ctx->arena,profiles,  " "),
        .paths      = NULL,
        .path_count = 0,
        .extras     = sync_extras,
        .dry_run    = opts->dry_run,
    };

    /* The pre-sync hook, once the run's profiles and its remote are known; a
     * dry run's too, told so (DOTTA_DRY_RUN=1). It gates the network, so sync
     * decides after it: each row's act is the decision's, after the fetch that
     * follows the hook, and nothing is asked. */
    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    /* The remote, met once (sys/remote.h): the open's listing is the epoch's
     * verdict and each row's remote head, every push's expectation, and its one
     * fetch brings the run's profiles and the epoch. Over the contact a progress
     * line, a terminal's alone, drawn over by transfer's frames while objects
     * move (sys/transfer.h transfer_op_end) and never a line of the report
     * (base/output.h output_progress), taken down once the fetch is done, whichever
     * way it went. Nothing here asks whether the remote stands: the open looks
     * it up before any use and refuses it in Git's words. Either's failure is
     * the run's, said once, before any verdict, naming the act and the remote —
     * a refused credential in the words transfer's callback set for what was
     * offered (sys/transfer.c transfer_credentials_callback), any other failure
     * in libgit2's — or the tracking ref the fetch read, took out of a name's
     * way or wrote, naming it (sys/remote.h remote_fetch).
     *
     * The fetch asks for the run's profiles: fetching is driven by what the user
     * asked for — `dotta sync -p work` fetches only `work` — where the Manifest
     * block still reads the whole enabled set. Each is asked for whether or not
     * the remote has been seen to hold it, a branch here or none: a row with no
     * branch here comes back from what the fetch brings, and one the remote does
     * not advertise costs the fetch nothing. Each tracking ref it writes moves
     * forward alone, so where the remote left its line the ref stands, and the
     * relation reads the re-creation off it (sys/remote.h remote_relation_t).
     * The epoch's ref beside them, whenever the remote advertises it: its objects
     * are the reconcile's to judge, and nothing moves where the two agree. */
    output_progress(out, OUTPUT_NORMAL, "Fetching from '%s'...", remote_name);
    transfer_wire_t received = { 0 };
    err = remote_open(repo, remote_name, commit_action_word(COMMIT_ACTION_SYNC), out, &remote);
    if (!err) err = remote_fetch(remote, profiles, EPOCH_REF, &received);
    output_clear_line(out);
    if (err) goto cleanup;

    /* At verbose, what the fetch moved, where it moved anything (an up-to-date
     * fetch says nothing): one op and one pack, so one wire, never a profile's
     * (lib/libgit2/include/git2/indexer.h git_indexer_progress) */
    if (received.objects > 0) {
        output_print(out, OUTPUT_VERBOSE, "{green}✓{reset} Fetched from '%s'", remote_name);
        sync_print_wire(out, received);
        output_endline(out, OUTPUT_VERBOSE);
    }

    /* Reconcile the repository epoch with the remote, before any profile acts:
     * its census reads the local branches, which the fetch leaves and a pull
     * moves, and an adopt the objects the fetch brought. */
    sync_reconcile_epoch(ctx, remote, remote_name, opts);

    /* The run, decided whole before any row acts: each row read against the remote,
     * its act off its reading, a merge's draft opened, so a conflict refuses
     * its row before anything moves — read by the preview, the act and the receipt,
     * none of which decides again */
    rows = sync_decide(ctx, remote, profiles, opts);

    /* A dry run ends here, its preview shown, and nothing pulled or pushed: the
     * fetch moved tracking refs forward alone, and a merge's open wrote the blobs
     * Git's clean merges compose, which nothing names. It builds no view: the
     * view a pull would leave is unknown without the pull. The answer still stands
     * — a row the decision refused is a question the dry run failed to answer,
     * not a profile it found no work for. */
    if (opts->dry_run) {
        sync_print_preview(out, remote_name, &rows, opts->no_push, opts->conflicts_side);
        output_summary(out, OUTPUT_NORMAL, "Dry run: nothing was pulled or pushed");
        sync_print_remedies(out, remote_name, &rows);
        err = sync_failure(ctx->arena, &rows);
        goto cleanup;
    }

    /* The view before the acts, the run's own, built after the pre-sync hook: a
     * commit the hook makes is in both views and no act's (sync_view) */
    manifest_t *before = sync_view(ctx);

    /* The act: every verdict carried out — a merge's draft committed, its conflicts
     * settled for the run's side at its open — and nothing said but the remote's
     * words a push brings (sync_execute). Git only — no state is written, so
     * the write lock is never held across network IO. Nothing catches up afterwards
     * either: the view is computed, and the block that follows only reports what
     * the act did to it. */
    sync_execute(ctx, remote, remote_name, &rows, opts);

    /* The receipt, once every act is done, a row for every profile */
    sync_print_receipt(out, remote_name, &rows, opts->no_push, opts->conflicts_side);

    /* The view after the acts, and the Manifest block where both views stand,
     * attributed to every enabled row (sync_print_manifest) */
    manifest_t *after = sync_view(ctx);
    if (before && after) sync_print_manifest(ctx, &enabled_profiles, before, after);

    if (after) {
        /* The import's health, in the receipt's own shape and apply's: the paths
         * a profile carries that this machine will not land, a section each.
         * The Manifest block above names none of them — it counts claims standing
         * in a view, and none of them is a row of the view after — so this is
         * the import moment's only signal of each, and the moment the paths are
         * worth naming rather than counting, an import being what brought them.
         * Every repair is generic: the (from P) beside every path names the
         * profiles, and a path holding a space would paste into a command it
         * breaks. */
        manifest_unbound_t unbound = manifest_unbound(after);
        if (unbound.count > 0) {
            output_section(out, OUTPUT_NORMAL, "Paths with no target");
            for (size_t i = 0; i < unbound.count && i < LIST_LIMIT; i++) {
                output_print(
                    out, OUTPUT_NORMAL,
                    "  {yellow}✗{reset} %s%s {dim}(from %s){reset}\n",
                    unbound.entries[i].storage_path,
                    path_kind_suffix(unbound.entries[i].kind),
                    unbound.entries[i].profile
                );
            }
            if (unbound.count > LIST_LIMIT) {
                output_print(
                    out, OUTPUT_NORMAL, "  ... and %zu more\n",
                    unbound.count - LIST_LIMIT
                );
            }
            output_info(
                out, OUTPUT_NORMAL,
                "  Their profile has no deployment target here, so nothing lands them"
            );
            output_info(
                out, OUTPUT_NORMAL,
                "  Set one with 'dotta profile enable <profile> --target /path'"
            );
        }

        /* Its sibling: a name the view did not keep is in the profile and in no
         * row either. `--dry-run` is the safety on the way out — dropping a
         * directory name takes every claim beneath it, and the preview shows
         * that rather than asserting it. */
        manifest_unkept_t unkept = manifest_unkept(after);
        if (unkept.count > 0) {
            output_section(out, OUTPUT_NORMAL, "Unused paths");
            for (size_t i = 0; i < unkept.count && i < LIST_LIMIT; i++) {
                output_print(
                    out, OUTPUT_NORMAL,
                    "  {yellow}✗{reset} %s%s {dim}(from %s){reset}\n",
                    unkept.entries[i].storage_path,
                    path_kind_suffix(unkept.entries[i].kind),
                    unkept.entries[i].profile
                );
            }
            if (unkept.count > LIST_LIMIT) {
                output_print(
                    out, OUTPUT_NORMAL, "  ... and %zu more\n",
                    unkept.count - LIST_LIMIT
                );
            }
            output_info(
                out, OUTPUT_NORMAL,
                "  The same profile names each of these places otherwise; "
                "'dotta status -v' pairs them"
            );
            output_info(
                out, OUTPUT_NORMAL,
                "  Drop one with 'dotta remove --dry-run <profile> <path>'"
            );
        }

        /* The third: a claim the profile's own claims leave no room is in the
         * profile and in no row — a sync's merge composes none (core/profiles.h
         * profile_draft_merge), but a pull brings one a hand committed elsewhere,
         * and any act brings a pair of names two of this machine's labels place
         * on one chain — so the import is where it is first named. The remedy
         * turns on the pair's shape, which status -v prints, as apply's section
         * says. */
        manifest_contradicted_t contradicted = manifest_contradicted(after);
        if (contradicted.count > 0) {
            output_section(out, OUTPUT_NORMAL, "Contradicted paths");
            for (size_t i = 0; i < contradicted.count && i < LIST_LIMIT; i++) {
                output_print(
                    out, OUTPUT_NORMAL, "  {yellow}✗{reset} %s%s {dim}(from %s){reset}\n",
                    contradicted.entries[i].storage_path,
                    path_kind_suffix(contradicted.entries[i].kind),
                    contradicted.entries[i].profile
                );
            }
            if (contradicted.count > LIST_LIMIT) {
                output_print(
                    out, OUTPUT_NORMAL, "  ... and %zu more\n",
                    contradicted.count - LIST_LIMIT
                );
            }
            output_info(
                out, OUTPUT_NORMAL,
                "  Another claim of the same profile leaves each no room, so nothing "
                "lands them"
            );
            output_info(
                out, OUTPUT_NORMAL,
                "  'dotta status -v' pairs each with its file or directory, and says how to "
                "keep one or the other"
            );
        }
    }

    /* The run's summary, beneath the receipt and what it did to the view, then
     * the remedies its rows call for */
    sync_print_summary(out, remote_name, &rows);
    sync_print_remedies(out, remote_name, &rows);

    /* Post-sync fires once the report is done — the receipt, the manifest block,
     * the summary and its hints; a failed build was warned above and is not a
     * reason to skip it. Nor is a profile that failed: the acts that did land
     * are real, and the hook's subject is the world sync leaves behind, not what
     * sync returns. */
    hook_fire_post(config, out, &hook_inv);

    /* The report is printed; the return value is what the caller reads. */
    err = sync_failure(ctx->arena, &rows);

cleanup:
    /* The handles the run holds: each merge's draft, whose free undoes nothing
     * in the repository (core/profiles.h profile_draft_free), and the remote,
     * whose free commits the credential helper's verdict (sys/remote.h
     * remote_free). state is borrowed from the dispatcher, and sync opens no
     * transaction and writes nothing; the rows are the command arena's. */
    for (size_t i = 0; i < rows.count; i++) {
        profile_draft_free(rows.entries[i].draft);
    }
    remote_free(remote);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The conflicts' side the line names, judged before the store opens, a word neither
 * of the two refusing the line: ours or theirs, --conflicts' alone.
 */
static error_t sync_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_sync_options_t *o = opts_v;

    /* No side named is PROFILE_SIDE_NONE, the options' zero */
    if (!o->conflicts) return NULL;
    if (strcmp(o->conflicts, "ours") == 0) {
        o->conflicts_side = PROFILE_SIDE_OURS;
    } else if (strcmp(o->conflicts, "theirs") == 0) {
        o->conflicts_side = PROFILE_SIDE_THEIRS;
    } else {
        return error_create(
            ERR_INVALID_ARG, "Unknown side '%s' for --conflicts (valid: ours, theirs)",
            o->conflicts
        );
    }
    return NULL;
}

/**
 * What can stand at the cursor: an enabled profile, by -p or bare; for --conflicts,
 * a side.
 */
static args_want_t sync_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    const dotta_ctx_t *ctx = ctx_v;

    if (ARGS_VALUE_IS(at, cmd_sync_options_t, conflicts)) {
        fputs("ours\tKeep the local side of every conflict\n", out);
        fputs("theirs\tKeep the remote's side of every conflict\n", out);
        return ARGS_WANT_NONE;
    }

    completion_profiles(ctx, out, COMPLETION_ENABLED);
    return ARGS_WANT_NONE;
}

static error_t sync_dispatch(const void *ctx_v, void *opts_v) {
    const dotta_ctx_t *ctx = ctx_v;
    return cmd_sync(ctx, (const cmd_sync_options_t *) opts_v);
}

static const args_opt_t sync_opts[] = {
    ARGS_GROUP("Options:"),
    ARGS_APPEND(
        "p profile",       "<name>",
        cmd_sync_options_t,profiles,  profile_count,
        "Filter sync to profile(s) (repeatable)"
    ),
    ARGS_FLAG(
        "n dry-run",
        cmd_sync_options_t,dry_run,
        "Preview without pulling or pushing"
    ),
    ARGS_FLAG(
        "no-push",
        cmd_sync_options_t,no_push,
        "Leave the remote as it is; skip every push"
    ),
    ARGS_STRING(
        "conflicts",       "<side>",
        cmd_sync_options_t,conflicts,
        "Keep one side of every conflict: ours or theirs"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_sync_options_t,verbosity, DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    /* Bare profile positionals funnel into the same APPEND field. */
    ARGS_POSITIONAL_ANY(
        cmd_sync_options_t,profiles,  profile_count
    ),
    ARGS_END,
};

const args_command_t spec_sync = {
    .name        = "sync",
    .summary     = "Synchronize profiles with remote repository",
    .usage       = "%s sync [options] [profile]...",
    .description =
        "Fetch, analyze, and reconcile enabled profiles with their\n"
        "remote counterparts. Only commits move: commit local edits\n"
        "with '%s update' first, and bring what a pull changed onto\n"
        "disk with '%s apply'.\n",
    .notes       =
        "Each Profile:\n"
        "  Local commits are pushed and the remote's pulled; a profile both\n"
        "  sides changed is merged, then pushed. A profile another machine\n"
        "  deleted is deleted locally too, and one it recreated replaces the\n"
        "  local one, unless this machine holds commits the remote never had:\n"
        "  then the profile is kept as it stands, and the sync says how to\n"
        "  keep those commits or let them go. An enabled profile with no\n"
        "  local branch gets it back where the remote holds it.\n"
        "\n"
        "Conflicts:\n"
        "  A merge combines changes to different files, lines and\n"
        "  permissions. Where both sides changed the same thing differently,\n"
        "  the profile is not merged and each conflict is listed: --conflicts\n"
        "  ours keeps the local side of every one, --conflicts theirs the\n"
        "  remote's. The side not kept stays in the profile's history.\n",
    .examples    =
        "  %s sync                         # All enabled profiles\n"
        "  %s sync global                  # Single profile\n"
        "  %s sync global darwin           # Multiple profiles\n"
        "  %s sync -n                      # Preview without pulling or pushing\n"
        "  %s sync --no-push               # Pull and merge, push nothing\n"
        "  %s sync --conflicts theirs      # Keep the remote's side of every conflict\n",
    .epilogue    =
        "See also:\n"
        "  %s update          # Commit local changes first\n"
        "  %s status --remote # Inspect remote state before syncing\n",
    .opts_size   = sizeof(cmd_sync_options_t),
    .opts        = sync_opts,
    .post_parse  = sync_post_parse,
    .complete    = sync_complete,
    .payload     = &(const dotta_needs_t){
        .repo    = DOTTA_REPO_OPEN,
        .state   = DOTTA_STATE_READ,
    },
    .dispatch    = sync_dispatch,
};
