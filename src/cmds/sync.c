/**
 * sync.c - Intelligent synchronization command
 */

#include "cmds/sync.h"

#include <config.h>
#include <git2.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "base/arena.h"
#include "base/args.h"
#include "base/array.h"
#include "base/error.h"
#include "base/output.h"
#include "cmds/completion.h"
#include "core/manifest.h"
#include "core/scope.h"
#include "core/state.h"
#include "core/workspace.h"
#include "crypto/keymgr.h"
#include "infra/epoch.h"
#include "sys/gitops.h"
#include "sys/resolve.h"
#include "sys/transfer.h"
#include "sys/upstream.h"
#include "utils/config.h"
#include "utils/hooks.h"

#define LIST_LIMIT 20  /* Every capped list in this file trims here. */

/**
 * The act the run carries out on a profile
 *
 * One verdict a row, decided once from what the analysis read and the run's options
 * (sync_decide), and read by the preview, the question, the act and the receipt:
 * none decides again, core/cleanup.h's stance. Each names one mechanism — a push
 * and a force push the transfer's (sys/gitops.h), a pull the fast-forward
 * (sync_fast_forward), a rebase, a merge and a reset sys/resolve's. A force push
 * and a reset discard the other side's commits, and a run's are of one kind,
 * its strategy's: ours force pushes, theirs resets. A person confirms them where
 * the configuration asks (cmd_sync).
 *
 * None is a row with nothing to carry out: the sides agree, there is no local
 * branch, warn leaves a divergence to the user, or the user's word withheld the
 * act its state called for.
 */
typedef enum {
    SYNC_VERDICT_NONE,          /* Nothing to carry out */
    SYNC_VERDICT_PUSH,          /* The local commits onto the remote, or the branch it lacks */
    SYNC_VERDICT_PULL,          /* The remote's commits, fast-forwarded */
    SYNC_VERDICT_REBASE,        /* A divergence: the local commits onto the remote's, then pushed */
    SYNC_VERDICT_MERGE,         /* A divergence: the remote's commits merged in, then pushed */
    SYNC_VERDICT_FORCE_PUSH,    /* ours: the local branch over the remote's, the remote's commits discarded */
    SYNC_VERDICT_RESET          /* theirs: the local branch to the remote's, the local commits discarded */
} sync_verdict_t;

/**
 * Whose word withholds an act: the user's own, given before the run — each
 * withholds the acts of its direction (sync_decide), said on the row beside the
 * act (sync_print_withheld)
 */
typedef enum {
    SYNC_REASON_NO_PUSH,        /* --no-push: every move to the remote */
    SYNC_REASON_NO_PULL,        /* --no-pull: every move that takes the remote's commits */
    SYNC_REASON_AUTO_PULL       /* auto_pull = false: the fast-forward */
} sync_reason_t;

/**
 * What carrying a row's verdict out came to — read by the receipt
 * (sync_print_receipt) and the glyph its rows lead with (sync_print_lead), and,
 * through the row's error, by the run's failure (sync_failure)
 */
typedef enum {
    SYNC_OUTCOME_NONE,          /* Not carried out: no act, or the run stopped before the row */
    SYNC_OUTCOME_DONE,          /* The act carried out whole */
    SYNC_OUTCOME_UP_TO_DATE,    /* A pull found the branch at the remote's head: another process moved it */
    SYNC_OUTCOME_FAILED,        /* The act failed, its cause the row's error */
    SYNC_OUTCOME_ROLLED_BACK,   /* A resolution undone: its verification or its push failed */
    SYNC_OUTCOME_UNVERIFIED     /* A reset that moved the branch, then failed its verification */
} sync_outcome_t;

/**
 * A profile in the run: what the analysis read of it, what the run decided, what
 * the act did
 *
 * Each column is written once, by its phase: the analysis the upstream, the
 * decision the verdict and what the user's word withholds, the act the outcome.
 * A withheld act leaves its row as it stands, its verdict none — but a rebase
 * or a merge under --no-push, which resolves all the same and withholds its push
 * alone. The row's error is the failure the run met for it, whichever phase met
 * it — said on the row's line, counted and named by sync_failure. A row whose
 * analysis failed has no verdict, and every reader asks its error before its
 * state: a failed analysis's zeroed state reads as up to date otherwise.
 */
typedef struct {
    const char *profile;        /* The scope's own name, borrowed */
    upstream_info_t upstream;   /* The analysis's: the state, each side's commits */
    sync_verdict_t verdict;     /* The act the run carries out */
    sync_verdict_t withheld;    /* The act the user's word keeps from the row; NONE where none */
    sync_reason_t reason;       /* Whose word, read beside an act withheld */
    sync_outcome_t outcome;     /* What carrying the verdict out came to */
    error_t error;              /* The failure's cause, borrowed; NULL where the run met none */
} sync_row_t;

/** The rows: one per profile in the sync scope, in its order — a value of the command arena */
typedef struct {
    sync_row_t *entries;
    size_t count;
} sync_rows_t;

/**
 * What the workspace guard found (sync_guard): what a pull of the run's scope
 * puts at risk, and the conflicts among it — both read by the consent cmd_sync
 * asks over them
 */
typedef struct {
    size_t blocking;   /* Update's work and the conflicts: what the consent is asked over */
    size_t conflicts;  /* Status's Conflicts, no default verb: the cancel's remedies turn on it */
} sync_guard_t;

/**
 * A verdict's word: the act a row says was withheld (sync_print_withheld), and
 * the resolution a rollback's refusal names (sync_rollback)
 */
static const char *sync_verdict_name(sync_verdict_t verdict) {
    switch (verdict) {
        case SYNC_VERDICT_PUSH:       return "push";
        case SYNC_VERDICT_PULL:       return "pull";
        case SYNC_VERDICT_REBASE:     return "rebase";
        case SYNC_VERDICT_MERGE:      return "merge";
        case SYNC_VERDICT_FORCE_PUSH: return "force push";
        case SYNC_VERDICT_RESET:      return "reset";
        case SYNC_VERDICT_NONE:       break;
    }

    CHECK_ARG(false, "a verdict that names no act");
}

/** A reason's word: the user's, as it was given — the flag, or the key's setting */
static const char *sync_reason_name(sync_reason_t reason) {
    switch (reason) {
        case SYNC_REASON_NO_PUSH:   return "--no-push";
        case SYNC_REASON_NO_PULL:   return "--no-pull";
        case SYNC_REASON_AUTO_PULL: return "auto_pull = false";
    }

    CHECK_ARG(false, "a reason no enumerator names");
}

/**
 * Fetch the scope's profiles from the remote
 *
 * Operates on the scope's profiles (scope_profiles): fetching is driven by what
 * the user asked for. `dotta sync -p work` fetches only `work`, not every enabled
 * profile. Precedence-adjacent work (the Manifest block) still uses the full
 * enabled set — different role, different accessor.
 *
 * Each is asked for whether or not the remote has been seen to hold it: the
 * analysis reads a profile through its remote-tracking ref (sys/upstream.h
 * upstream_analyze_profile), so one the remote holds and no fetch here ever asked
 * for would read as never pushed — and one the remote does not hold costs the
 * fetch nothing (sys/gitops.h gitops_fetch_branches).
 *
 * Nothing here asks whether the remote stands: the fetch looks it up before any
 * use and refuses it in Git's words, as every verb that takes a remote name does
 * (sys/gitops.h gitops_resolve_default_remote).
 */
static error_t sync_fetch(
    const dotta_ctx_t *ctx,
    const char *remote_name,
    const scope_t *scope,
    transfer_context_t *xfer
) {
    CHECK_NULL(ctx);
    CHECK_NULL(remote_name);
    CHECK_NULL(scope);

    output_t *out = ctx->out;

    /* Ephemeral fetch progress — shown while fetching, cleared after. On TTY:
     * transfer progress overwrites via \r, then line cleared entirely. On pipe:
     * falls back to persistent line with newline. */
    output_print(out, OUTPUT_NORMAL, "Fetching from '%s'...", remote_name);
    fflush(out->stream);

    /* Perform batched fetch - single network operation for all branches */
    error_t err = gitops_fetch_branches(
        ctx->run.repo, remote_name, scope_profiles(scope), xfer
    );

    /* The announce line ends here. Progress drawn over it ended with its op
     * (sys/transfer.h transfer_op_end), whichever way the op went, so what can
     * stand is the announce alone — an up-to-date fetch draws nothing over it:
     * cleared on a terminal, ended on a pipe. */
    if (output_is_tty(out)) {
        output_clear_line(out);
    } else {
        output_endline(out, OUTPUT_NORMAL);
    }

    /* The fetch's own error, which names the remote and the act: a refused
     * credential in the words the transfer's callback set for what was offered
     * (sys/transfer.c transfer_credentials_callback), any other failure — a ref
     * write as well as a network — in libgit2's */
    return err;
}

/**
 * The rows: one per profile in the sync scope, in its order, each holding its
 * branch's state against the remote
 *
 * The table is made here, in `arena`, as scope_profiles(scope) orders it — the
 * profiles the user asked for, each one the fetch asked the remote for, held
 * there or not. A row names its profile by the scope's own string. A profile
 * the analysis cannot read fails in its own row, by its error, which the decision
 * passes over and the preview and the receipt read back.
 */
static sync_rows_t sync_analyze(
    arena_t *arena,
    git_repository *repo,
    const char *remote_name,
    const scope_t *scope
) {
    CHECK_NULL(arena);
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(scope);

    const string_array_t *profiles = scope_profiles(scope);
    sync_rows_t rows = {
        .entries = arena_calloc(arena, profiles->count, sizeof(*rows.entries)),
        .count   = profiles->count,
    };

    for (size_t i = 0; i < rows.count; i++) {
        sync_row_t *row = &rows.entries[i];

        row->profile = profiles->entries[i];
        row->error = upstream_analyze_profile(
            repo, remote_name, row->profile, &row->upstream
        );
    }

    return rows;
}

/**
 * What a profile's state calls for under the strategy, before the user's word
 * withholds any of it: the act read off the state alone, as cleanup_verdict reads
 * an orphan's off the item
 *
 * ours and theirs act on a branch only behind or only ahead as well — ours force
 * pushes over the remote's newer commits, theirs resets the local ones away, as
 * the command's notes say (spec_sync) — and a branch the remote lacks is pushed
 * whatever the strategy: there is nothing to reset to, and nothing to force over.
 */
static sync_verdict_t sync_verdict(upstream_state_t state, sync_strategy_t strategy) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:
        case UPSTREAM_NO_LOCAL:
            return SYNC_VERDICT_NONE;

        case UPSTREAM_NO_REMOTE:
            return SYNC_VERDICT_PUSH;

        case UPSTREAM_LOCAL_AHEAD:
            return strategy == SYNC_STRATEGY_THEIRS ? SYNC_VERDICT_RESET : SYNC_VERDICT_PUSH;

        case UPSTREAM_REMOTE_AHEAD:
            return strategy == SYNC_STRATEGY_OURS ? SYNC_VERDICT_FORCE_PUSH : SYNC_VERDICT_PULL;

        case UPSTREAM_DIVERGED:
            switch (strategy) {
                case SYNC_STRATEGY_WARN:   return SYNC_VERDICT_NONE;
                case SYNC_STRATEGY_REBASE: return SYNC_VERDICT_REBASE;
                case SYNC_STRATEGY_MERGE:  return SYNC_VERDICT_MERGE;
                case SYNC_STRATEGY_OURS:   return SYNC_VERDICT_FORCE_PUSH;
                case SYNC_STRATEGY_THEIRS: return SYNC_VERDICT_RESET;
            }
            break;
    }

    CHECK_ARG(false, "an upstream state or a strategy no enumerator names");
}

/**
 * Withhold the row's act whole: the row stays as the analysis read it, its line
 * saying the act and whose word kept it
 */
static void sync_withhold(sync_row_t *row, sync_reason_t reason) {
    row->withheld = row->verdict;
    row->reason = reason;
    row->verdict = SYNC_VERDICT_NONE;
}

/**
 * Decide the run whole, before any profile acts: each row's verdict, and what
 * the user's word withholds of it
 *
 * The strategy is --diverged's where given, else the configuration's, in the
 * same words — judged by the parse, before the store opened and the pre-sync
 * hook with it (sync_post_parse). Each word withholds the acts of its direction:
 * --no-push every move to the remote, --no-pull every move that takes the remote's
 * commits, and auto_pull = false the fast-forward, --no-pull's word read first.
 * A row whose analysis failed is passed over.
 *
 * @param rows The analysis's rows (must not be NULL), each decided in place
 * @param config The configuration: the strategy, and auto_pull (must not be NULL)
 * @param opts The options: --diverged, --no-push and --no-pull (must not be NULL)
 * @return The act the run discards commits by — the strategy's force push or
 *         reset, where one stands unwithheld — or SYNC_VERDICT_NONE: what the
 *         run's question is asked over (cmd_sync)
 */
static sync_verdict_t sync_decide(
    sync_rows_t *rows,
    const config_t *config,
    const cmd_sync_options_t *opts
) {
    CHECK_NULL(rows);
    CHECK_NULL(config);
    CHECK_NULL(opts);

    const sync_strategy_t strategy = opts->diverged
        ? opts->diverged_strategy : config->diverged_strategy;
    sync_verdict_t discarding = SYNC_VERDICT_NONE;

    for (size_t i = 0; i < rows->count; i++) {
        sync_row_t *row = &rows->entries[i];
        if (row->error) continue;

        row->verdict = sync_verdict(row->upstream.state, strategy);

        switch (row->verdict) {
            case SYNC_VERDICT_NONE:
                break;

            case SYNC_VERDICT_PUSH:
            case SYNC_VERDICT_FORCE_PUSH:
                if (opts->no_push) sync_withhold(row, SYNC_REASON_NO_PUSH);
                break;

            case SYNC_VERDICT_PULL:
                if (opts->no_pull) {
                    sync_withhold(row, SYNC_REASON_NO_PULL);
                } else if (!config->auto_pull) {
                    sync_withhold(row, SYNC_REASON_AUTO_PULL);
                }
                break;

            case SYNC_VERDICT_RESET:
                if (opts->no_pull) sync_withhold(row, SYNC_REASON_NO_PULL);
                break;

            case SYNC_VERDICT_REBASE:
            case SYNC_VERDICT_MERGE:
                /* A resolution takes the remote's commits, so --no-pull withholds
                 * it whole; under --no-push it resolves all the same and its
                 * push is withheld — the next sync's, the branch then only ahead */
                if (opts->no_pull) {
                    sync_withhold(row, SYNC_REASON_NO_PULL);
                } else if (opts->no_push) {
                    row->withheld = SYNC_VERDICT_PUSH;
                    row->reason = SYNC_REASON_NO_PUSH;
                }
                break;
        }

        if (row->verdict == SYNC_VERDICT_FORCE_PUSH || row->verdict == SYNC_VERDICT_RESET) {
            discarding = row->verdict;
        }
    }

    return discarding;
}

/**
 * Fast-forward a branch to its remote-tracking ref, and nothing else; *updated
 * says whether it moved
 */
static error_t sync_fast_forward(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    bool *updated
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);
    CHECK_NULL(updated);

    *updated = false;

    /* Get local and remote refs */
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t err;

    err = gitops_branch_refname(
        local_refname, sizeof(local_refname), branch_name
    );
    if (err) return err;

    err = gitops_remote_branch_refname(
        remote_refname, sizeof(remote_refname), remote_name, branch_name
    );
    if (err) return err;

    /* The branch that moves, read through a symbolic one to the ref it names:
     * its target is what the fast-forward compares and sets. Its absence is no
     * answer here — the caller asks of a branch it holds — so the lookup's failure
     * is the failure. */
    git_reference *branch = NULL;
    int rc = git_reference_lookup(&branch, repo, local_refname);
    if (rc < 0) return error_git(rc, "Cannot fast-forward '%s'", branch_name);

    git_reference *local_ref = NULL;
    rc = git_reference_resolve(&local_ref, branch);
    git_reference_free(branch);
    if (rc < 0) return error_git(rc, "Cannot fast-forward '%s'", branch_name);
    const git_oid *local_oid = git_reference_target(local_ref);

    /* The remote-tracking head, or its absence proven (sys/gitops.h
     * gitops_reference_oid): nothing fetched for the branch is nothing to do,
     * and a packed-refs that will not parse is the failure it is, never a remote
     * branch that is not there. */
    git_oid remote_oid;
    err = gitops_reference_oid(repo, remote_refname, &remote_oid);
    if (err || git_oid_is_zero(&remote_oid)) {
        git_reference_free(local_ref);
        return err;
    }

    /* Check if branches are at the same commit (up-to-date) */
    if (git_oid_equal(local_oid, &remote_oid)) {
        git_reference_free(local_ref);
        /* Already up-to-date, nothing to do */
        return NULL;
    }

    /* Check if fast-forward is possible by checking if local is ancestor of remote.
     * A graph question about the two commits, independent of HEAD: the store
     * checks nothing out, and the branch being moved is never the current one. */
    rc = git_graph_descendant_of(repo, &remote_oid, local_oid);
    if (rc < 0) {
        git_reference_free(local_ref);
        return error_git(rc, "Cannot fast-forward '%s'", branch_name);
    }

    if (rc == 0) {
        /* local is NOT an ancestor of remote - cannot fast-forward */
        git_reference_free(local_ref);
        return error_create(
            ERR_CONFLICT, "Cannot fast-forward '%s' - branches have diverged",
            branch_name
        );
    }

    /* rc == 1 means local IS an ancestor of remote - can fast-forward */

    /* Perform fast-forward */
    git_reference *updated_ref = NULL;
    rc = git_reference_set_target(
        &updated_ref, local_ref, &remote_oid, "sync: Fast-forward pull"
    );
    git_reference_free(local_ref);

    if (rc < 0) return error_git(rc, "Cannot fast-forward '%s'", branch_name);

    git_reference_free(updated_ref);
    *updated = true;

    return NULL;
}

/**
 * Roll a resolution back to the head the branch stood at before it, after its
 * `step` — "verification" or "push" — failed: the row rolled back, or, where
 * the rollback fails, the run's error, naming the step — the branch left where
 * the resolution put it, the row failed by that step
 */
static error_t sync_rollback(
    resolve_context_t *resolve,
    sync_row_t *row,
    const char *step
) {
    error_t err = resolve_rollback(resolve);
    row->outcome = err ? SYNC_OUTCOME_FAILED : SYNC_OUTCOME_ROLLED_BACK;
    if (!err) return NULL;

    /* The error names the head, the one fact a repair starts from: whole, as
     * git's own ref refusals spell an id (lib/git/refs/packed-backend.c,
     * oid_to_hex), where an abbreviation could name two commits. The branch is
     * its cause's to name (sys/gitops.c gitops_update_branch_reference). */
    char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
    git_oid_tostr(oid_str, sizeof(oid_str), &resolve->saved_oid);
    return error_wrap(
        err, "Cannot roll back to %s, the branch's head before the %s, "
        "after the %s failed", oid_str, sync_verdict_name(row->verdict), step
    );
}

/**
 * Carry a rebase or a merge out: the resolution, its verification, then its push
 * unless --no-push withheld it
 *
 * A step that fails is the row's, its cause as it stands: each names its act
 * and its branch (sys/resolve.h, sys/gitops.h). The resolution runs in memory
 * and moves the branch alone, never HEAD, so one that fails leaves the branch
 * where it stood; a verification or a push that fails after it rolls the branch
 * back.
 *
 * @return The run's error where that rollback fails; NULL otherwise, every other
 *         failure the row's
 */
static error_t sync_resolve(
    git_repository *repo,
    const char *remote_name,
    sync_row_t *row,
    transfer_context_t *xfer
) {
    /* The context keeps the head the branch stands at, the rollback's target */
    resolve_context_t resolve;
    error_t err = resolve_init(
        &resolve, repo, remote_name, row->profile,
        row->verdict == SYNC_VERDICT_REBASE ? RESOLVE_STRATEGY_REBASE : RESOLVE_STRATEGY_MERGE
    );
    if (!err) err = resolve_execute(&resolve, NULL);
    if (err) {
        row->error = err;
        row->outcome = SYNC_OUTCOME_FAILED;
        return NULL;
    }

    err = resolve_verify(&resolve, NULL, NULL);
    if (err) {
        row->error = err;
        return sync_rollback(&resolve, row, "verification");
    }

    if (row->withheld != SYNC_VERDICT_PUSH) {
        err = gitops_push_branch(repo, remote_name, row->profile, xfer);
        if (err) {
            row->error = err;
            return sync_rollback(&resolve, row, "push");
        }
    }

    row->outcome = SYNC_OUTCOME_DONE;
    return NULL;
}

/**
 * Carry a reset out: the local branch to the remote's head, its own commits
 * discarded
 *
 * A step that fails before the branch moves leaves it where it stood. None after
 * is rolled back: theirs already put the branch where the user asked, and rolling
 * back would undo it — a verification that fails is said beside the branch it
 * moved (SYNC_OUTCOME_UNVERIFIED).
 */
static void sync_reset(git_repository *repo, const char *remote_name, sync_row_t *row) {
    resolve_context_t resolve;
    error_t err = resolve_init(
        &resolve, repo, remote_name, row->profile, RESOLVE_STRATEGY_THEIRS
    );
    if (!err) err = resolve_execute(&resolve, NULL);
    if (err) {
        row->error = err;
        row->outcome = SYNC_OUTCOME_FAILED;
        return;
    }

    row->error = resolve_verify(&resolve, NULL, NULL);
    row->outcome = row->error ? SYNC_OUTCOME_UNVERIFIED : SYNC_OUTCOME_DONE;
}

/**
 * Carry every verdict out, in the scope's order, printing nothing: what each
 * act came to, and the failure it met, written on its row for the receipt
 *
 * Git only: every pull, rebase, merge and reset moves a branch head and nothing
 * else, and what the acts did to the view is read off once, for every enabled
 * profile, in cmd_sync's Manifest block. Each verdict is one mechanism, called
 * as the decision named it: nothing here decides again.
 *
 * @return The run's error where a resolution's rollback failed — the rows after
 *         it left as decided, their outcome none — or NULL: every other failure
 *         is its row's
 */
static error_t sync_execute(
    git_repository *repo,
    const char *remote_name,
    sync_rows_t *rows,
    transfer_context_t *xfer
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(rows);

    for (size_t i = 0; i < rows->count; i++) {
        sync_row_t *row = &rows->entries[i];

        switch (row->verdict) {
            case SYNC_VERDICT_NONE:
                break;

            case SYNC_VERDICT_PUSH:
                row->error = gitops_push_branch(repo, remote_name, row->profile, xfer);
                row->outcome = row->error ? SYNC_OUTCOME_FAILED : SYNC_OUTCOME_DONE;
                break;

            case SYNC_VERDICT_FORCE_PUSH:
                row->error = gitops_force_push_branch(repo, remote_name, row->profile, xfer);
                row->outcome = row->error ? SYNC_OUTCOME_FAILED : SYNC_OUTCOME_DONE;
                break;

            case SYNC_VERDICT_PULL: {
                /* The fast-forward answers whether it moved the branch: one that
                 * finds it at the remote's head already met another process's
                 * pull since the analysis, an outcome of its own */
                bool moved = false;
                row->error = sync_fast_forward(repo, remote_name, row->profile, &moved);
                row->outcome = row->error ? SYNC_OUTCOME_FAILED
                    : moved ? SYNC_OUTCOME_DONE : SYNC_OUTCOME_UP_TO_DATE;
                break;
            }

            case SYNC_VERDICT_REBASE:
            case SYNC_VERDICT_MERGE: {
                error_t err = sync_resolve(repo, remote_name, row, xfer);
                if (err) return err;
                break;
            }

            case SYNC_VERDICT_RESET:
                sync_reset(repo, remote_name, row);
                break;
        }
    }

    return NULL;
}

/**
 * Print a row's lead: its glyph, then its profile — the words every row of the
 * table sets before its clause
 *
 * The glyph is read off the row alone, alike in both tenses: ✗ where the row
 * holds an error — exactly the rows the run's failure counts (sync_failure) — ✓
 * where an act was carried out whole, and otherwise the state the row stands
 * in, sys/upstream.h's face for it, read as status's rows read it (cmds/status.c
 * status_print_remote). The glyph alone carries the row's colour; the profile
 * is cyan, as every screen spells one.
 */
static void sync_print_lead(output_t *out, const sync_row_t *row) {
    if (row->error) {
        output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_RED, "  ✗");
    } else if (row->outcome == SYNC_OUTCOME_DONE) {
        output_colored(out, OUTPUT_NORMAL, OUTPUT_COLOR_GREEN, "  ✓");
    } else {
        /* Where it stands: as the analysis read it, or up to date where the pull
         * found it so, another process's pull before it */
        const upstream_state_t state = row->outcome == SYNC_OUTCOME_UP_TO_DATE
            ? UPSTREAM_UP_TO_DATE : row->upstream.state;
        output_colored(
            out, OUTPUT_NORMAL, upstream_state_color(state), "  %s",
            upstream_state_symbol(state)
        );
    }
    output_print(out, OUTPUT_NORMAL, " {cyan}%s{reset}: ", row->profile);
}

/**
 * Print where a row no act moved stands, alike in both tenses: its state's phrase
 * (sys/upstream.h upstream_state_phrase), or the analysis's failure where it
 * read none
 *
 * The clause of a row the run does not act on, in the preview and the receipt
 * alike, so the two tenses cannot drift — and of a row the run stopped before,
 * a rollback that failed above it: nothing moved it, and the run's error says
 * why it went unreached.
 */
static void sync_print_state(output_t *out, const sync_row_t *row) {
    if (row->error) {
        output_print(out, OUTPUT_NORMAL, "%s", error_line(row->error));
        return;
    }

    char phrase[UPSTREAM_PHRASE_MAX];
    upstream_state_phrase(&row->upstream, phrase, sizeof(phrase));
    output_print(out, OUTPUT_NORMAL, "%s", phrase);
}

/**
 * Print what the user's word withheld of the row's act, after its clause: the
 * act, and whose word kept it (sync_decide) — nothing on a failed row, whose
 * clause is its cause alone
 */
static void sync_print_withheld(output_t *out, const sync_row_t *row) {
    if (row->error || row->withheld == SYNC_VERDICT_NONE) return;

    output_print(
        out, OUTPUT_NORMAL, ", %s skipped (%s)",
        sync_verdict_name(row->withheld), sync_reason_name(row->reason)
    );
}

/**
 * Print the remedies the rows call for, closing the table: one line a family,
 * said once however many rows call for it
 *
 * One family: a divergence warn leaves — no failure, no act, and no word of the
 * user's that withheld one; under any other strategy a divergence has its act,
 * or its row says the word that kept it. The line names the flag and the key,
 * and the strategies that resolve by their words (utils/config.h
 * config_strategies), warn left out; what each does is --help's and completion's.
 */
static void sync_print_remedies(output_t *out, const sync_rows_t *rows) {
    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        if (!row->error && row->upstream.state == UPSTREAM_DIVERGED &&
            row->verdict == SYNC_VERDICT_NONE && row->withheld == SYNC_VERDICT_NONE) {
            output_print(
                out, OUTPUT_NORMAL,
                "  Use --diverged=<strategy> or set diverged_strategy in config: "
            );

            /* Every strategy but warn's, in the vocabulary's order: ", " between
             * two, " or " before the last */
            size_t left = CONFIG_STRATEGY_COUNT - 1;
            const char *sep = "";
            for (size_t s = 0; s < CONFIG_STRATEGY_COUNT; s++) {
                if (s == SYNC_STRATEGY_WARN) continue;

                output_print(out, OUTPUT_NORMAL, "%s%s", sep, config_strategies[s].name);
                left--;
                sep = left == 1 ? " or " : ", ";
            }
            output_endline(out, OUTPUT_NORMAL);
            return;
        }
    }
}

/**
 * Print the preview: what the run will do, profile by profile in the scope's
 * order, titled by the remote — a dry run's block, or the question's preamble
 * where one is asked
 *
 * The receipt's sibling (sync_print_receipt), in the future tense, each row in
 * the line both print: its lead, its clause, what the user's word withheld. A
 * row the run does not act on says where it stands, as the receipt says it
 * (sync_print_state); one it acts on, the act and what it discards. The remedies
 * its rows call for close it (sync_print_remedies).
 */
static void sync_print_preview(
    output_t *out,
    const char *remote_name,
    const sync_rows_t *rows
) {
    output_section(out, OUTPUT_NORMAL, "Sync preview for '{cyan}%s{reset}'", remote_name);

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];
        const upstream_info_t *up = &row->upstream;

        sync_print_lead(out, row);
        switch (row->verdict) {
            case SYNC_VERDICT_NONE:
                sync_print_state(out, row);
                break;

            case SYNC_VERDICT_PUSH:
                if (up->state == UPSTREAM_NO_REMOTE) {
                    output_print(
                        out, OUTPUT_NORMAL, "will create remote branch"
                    );
                } else {
                    output_print(
                        out, OUTPUT_NORMAL, "will push %zu commit%s",
                        up->ahead, up->ahead == 1 ? "" : "s"
                    );
                }
                break;

            case SYNC_VERDICT_PULL:
                output_print(
                    out, OUTPUT_NORMAL, "will pull %zu commit%s",
                    up->behind, up->behind == 1 ? "" : "s"
                );
                break;

            case SYNC_VERDICT_REBASE:
                output_print(
                    out, OUTPUT_NORMAL, "will rebase onto the remote%s",
                    row->withheld == SYNC_VERDICT_PUSH ? "" : ", then push"
                );
                break;

            case SYNC_VERDICT_MERGE:
                output_print(
                    out, OUTPUT_NORMAL, "will merge the remote%s",
                    row->withheld == SYNC_VERDICT_PUSH ? "" : ", then push"
                );
                break;

            case SYNC_VERDICT_FORCE_PUSH:
                output_print(
                    out, OUTPUT_NORMAL, "will force push, discarding the remote's %zu commit%s",
                    up->behind, up->behind == 1 ? "" : "s"
                );
                break;

            case SYNC_VERDICT_RESET:
                output_print(
                    out, OUTPUT_NORMAL, "will reset to the remote, discarding %zu local commit%s",
                    up->ahead, up->ahead == 1 ? "" : "s"
                );
                break;
        }
        sync_print_withheld(out, row);
        output_endline(out, OUTPUT_NORMAL);
    }

    sync_print_remedies(out, rows);
}

/**
 * Print what an act carried out whole did: the preview's act in the past tense
 * (sync_print_preview), with what it discarded
 */
static void sync_print_done(output_t *out, const sync_row_t *row) {
    const upstream_info_t *up = &row->upstream;

    switch (row->verdict) {
        case SYNC_VERDICT_NONE:
            break;  /* A row carried out has its act */

        case SYNC_VERDICT_PUSH:
            if (up->state == UPSTREAM_NO_REMOTE) {
                output_print(out, OUTPUT_NORMAL, "created remote branch");
            } else {
                output_print(
                    out, OUTPUT_NORMAL, "pushed %zu commit%s",
                    up->ahead, up->ahead == 1 ? "" : "s"
                );
            }
            break;

        case SYNC_VERDICT_PULL:
            output_print(
                out, OUTPUT_NORMAL, "pulled %zu commit%s",
                up->behind, up->behind == 1 ? "" : "s"
            );
            break;

        case SYNC_VERDICT_REBASE:
            output_print(
                out, OUTPUT_NORMAL, "rebased onto the remote%s",
                row->withheld == SYNC_VERDICT_PUSH ? "" : ", then pushed"
            );
            break;

        case SYNC_VERDICT_MERGE:
            output_print(
                out, OUTPUT_NORMAL, "merged the remote%s",
                row->withheld == SYNC_VERDICT_PUSH ? "" : ", then pushed"
            );
            break;

        case SYNC_VERDICT_FORCE_PUSH:
            output_print(
                out, OUTPUT_NORMAL, "force pushed, discarding the remote's %zu commit%s",
                up->behind, up->behind == 1 ? "" : "s"
            );
            break;

        case SYNC_VERDICT_RESET:
            output_print(
                out, OUTPUT_NORMAL, "reset to the remote, discarding %zu local commit%s",
                up->ahead, up->ahead == 1 ? "" : "s"
            );
            break;
    }
}

/**
 * Print the receipt: what each act came to, profile by profile in the scope's
 * order, titled by the remote, once every act is done
 *
 * The preview's sibling (sync_print_preview), in the past tense, each row in
 * the line both print: its lead, its clause, what the user's word withheld. An
 * act carried out whole is said in the preview's words (sync_print_done); a row
 * no act moved where it stands, as the preview says it (sync_print_state) — a
 * row the run stopped before among them, the run's error beneath saying why;
 * and a failure by its cause, beside where it left the branch. The remedies its
 * rows call for close it (sync_print_remedies).
 */
static void sync_print_receipt(
    output_t *out,
    const char *remote_name,
    const sync_rows_t *rows
) {
    output_section(out, OUTPUT_NORMAL, "Sync with '{cyan}%s{reset}'", remote_name);

    for (size_t i = 0; i < rows->count; i++) {
        const sync_row_t *row = &rows->entries[i];

        sync_print_lead(out, row);
        switch (row->outcome) {
            case SYNC_OUTCOME_NONE:
                /* No act, or the run stopped before the row: nothing moved it */
                sync_print_state(out, row);
                break;

            case SYNC_OUTCOME_DONE:
                sync_print_done(out, row);
                break;

            case SYNC_OUTCOME_UP_TO_DATE:
                /* What the pull found, not what it did */
                output_print(out, OUTPUT_NORMAL, "already up-to-date");
                break;

            case SYNC_OUTCOME_FAILED:
                output_print(out, OUTPUT_NORMAL, "%s", error_line(row->error));
                break;

            case SYNC_OUTCOME_ROLLED_BACK:
                output_print(out, OUTPUT_NORMAL, "%s, rolled back", error_line(row->error));
                break;

            case SYNC_OUTCOME_UNVERIFIED:
                /* The branch moved and stays where the reset put it, so the act
                 * comes first: what failed is the verification after it */
                output_print(
                    out, OUTPUT_NORMAL, "reset to the remote, unverified: %s",
                    error_line(row->error)
                );
                break;
        }
        sync_print_withheld(out, row);
        output_endline(out, OUTPUT_NORMAL);
    }

    sync_print_remedies(out, rows);
}

/**
 * The profiles the run's discarding act is for, each quoted, joined as a sentence
 * lists them — 'q', 'q' and 'r', 'p', 'q' and 'r' — in `arena`: the subject of
 * the run's question (sync_ask) and of its two refusals (sync_refusal)
 */
static const char *sync_discarded(arena_t *arena, const sync_rows_t *rows, sync_verdict_t act) {
    string_array_t profiles;
    string_array_init(&profiles, arena, 0);

    for (size_t i = 0; i < rows->count; i++) {
        if (rows->entries[i].verdict == act) {
            string_array_pushf(&profiles, "'%s'", rows->entries[i].profile);
        }
    }

    /* ", " between two names, " and " before the last, as apply joins its
     * question's parts */
    const char *joined = profiles.entries[0];
    for (size_t i = 1; i < profiles.count; i++) {
        joined = arena_str_format(
            arena, "%s%s%s", joined, i + 1 == profiles.count ? " and " : ", ",
            profiles.entries[i]
        );
    }

    return joined;
}

/**
 * Ask the run's one question: whether its discarding act may go ahead
 *
 * Asked beneath the preview, before any profile acts, of a person at a terminal
 * (base/output.h output_ask_destructive). It names the act and its profiles, so
 * a configured quiet, which prints no preview, still reads what it is asked;
 * what each discards is the preview's.
 */
static output_answer_t sync_ask(
    output_t *out,
    arena_t *arena,
    const sync_rows_t *rows,
    sync_verdict_t act
) {
    const char *profiles = sync_discarded(arena, rows, act);

    if (act == SYNC_VERDICT_RESET) {
        return output_ask_destructive(
            out, "Reset %s to the remote, discarding the local commits?", profiles
        );
    }
    return output_ask_destructive(out, "Force push %s over the remote's commits?", profiles);
}

/**
 * The run's refusal for want of the confirmation its discarding act owes
 *
 * One frame for two causes, `why` the cause none came: "which only a terminal
 * gives" at the decision, off a terminal, and "and none was read" once asked.
 * Read alone on stderr, it names the act and its profiles itself, and the key
 * that answers in advance in its own words.
 */
static error_t sync_refusal(
    arena_t *arena,
    const sync_rows_t *rows,
    sync_verdict_t act,
    const char *why
) {
    const char *profiles = sync_discarded(arena, rows, act);

    if (act == SYNC_VERDICT_RESET) {
        return error_create(
            ERR_VALIDATION, "Cannot reset %s to the remote without a confirmation, %s; "
            "confirm_destructive = false resets without asking", profiles, why
        );
    }
    return error_create(
        ERR_VALIDATION, "Cannot force push %s without a confirmation, %s; "
        "confirm_destructive = false pushes without asking", profiles, why
    );
}

/**
 * The run's failure, if it had one — the answer cmd_sync returns.
 *
 * A profile the run tried to reconcile and could not (a row with an error —
 * whatever the phase: the analysis, or the act: a pull, a resolution, a push, a
 * reset) is a broken promise, and only the return value carries that to the caller.
 * The reason was printed on the profile's own row — on stdout, so a redirected
 * sync's report never reads as a clean success — but a shell reads none of it.
 *
 * A profile the run deliberately left alone is not a failure: the caller's word
 * withheld its act (--no-push, --no-pull, auto_pull = false), or the configured
 * strategy did ('warn' on a divergence). Its own row is its whole report, and
 * `dotta sync && dotta apply` keeps working for everyone who syncs under 'warn'.
 *
 * Pure, and deliberately so: the per-profile errors stay in the rows that borrow
 * them and are never rethrown, since each was already said where it happened.
 * The message carries what no row says — how much of the run the failures were
 * — and names their profiles in the scope's order: the one line a configured
 * quiet, which says no row, reads which failed by.
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
 * Reached with encryption off alone: while it is on, the dispatch refuses a ref
 * that yields no epoch before any command runs (main.c open_run), naming the
 * same restore and, beside it, encryption.enabled = false — the one way a run
 * arrives here.
 */
static void sync_print_epoch_damaged(output_t *out, const char *remote_name) {
    output_gap(out, OUTPUT_NORMAL);
    output_warning(
        out, OUTPUT_NORMAL,
        "Repository epoch left alone: '%s' cannot be read and this repository "
        "holds encrypted files that may be sealed under it",
        EPOCH_REF
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
 * the chosen git action (establish via epoch_push, adopt via epoch_fetch). The
 * fact-finding already happened in infra/epoch; this layer is pure policy and
 * printing.
 *
 * Runs before the fetch phase so the decision's census is never contaminated by
 * pulled remote ciphertext. Every outcome is best-effort — a warning and the
 * rest of the sync — which is why nothing here is returned: the two errors the
 * resolve produces, a local ref that would not read and a census that could not
 * finish, are verdicts to print, not a run to fail.
 *
 * The epoch is machinery, so it says as little as it can get away with. Five of
 * the seven verdicts are a verbose line or nothing at all: dotta either did the
 * right thing or had nothing to do, and neither is the user's business at NORMAL.
 * What speaks up is what the user has to act on — a divergence over ciphertext,
 * a ref that cannot be read over ciphertext, and a resolve that could not decide
 * — and each is one line of finding plus one of remedy or cause. Nothing here
 * reports the census, the salt, or which of three routes reached an adopt.
 */
static void sync_reconcile_epoch(
    const dotta_ctx_t *ctx,
    const char *remote_name,
    transfer_context_t *xfer,
    const cmd_sync_options_t *opts
) {
    git_repository *repo = ctx->run.repo;
    keymgr *keymgr = ctx->run.keymgr;
    output_t *out = ctx->out;

    epoch_reconcile_t decision;
    error_t err = epoch_resolve(repo, remote_name, xfer, &decision);
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
    switch (decision) {
        case EPOCH_RECONCILE_UNREACHABLE:
            /* The authoritative "remote unreachable" error comes from the fetch
             * phase that runs next. */
            output_info(out, OUTPUT_VERBOSE, "Skipped epoch sync (remote unreachable)");
            return;

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
            /* The push's failure names its act, the ref and the remote, then
             * libgit2's reason (infra/epoch.c epoch_push): printed whole */
            err = epoch_push(repo, remote_name, xfer);
            if (err) {
                output_gap(out, OUTPUT_NORMAL);
                output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
                return;  /* best-effort; retried next sync */
            }
            output_success(
                out, OUTPUT_VERBOSE,
                "Established repository epoch on remote"
            );
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
             * claim about work that did not happen on the other two. Pull-shaped:
             * gate on --no-pull. */
            if (opts->no_pull) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Remote repository epoch differs; adopt skipped"
                );
                return;
            }
            if (opts->dry_run) {
                output_info(
                    out, OUTPUT_VERBOSE,
                    "Would adopt repository epoch from remote"
                );
                return;
            }

            kdf_epoch_t fetched;
            err = epoch_fetch(repo, remote_name, xfer, &fetched);
            if (err) {
                /* Every failure of the fetch names its act and leaves the local
                 * ref standing — one it could not adopt was judged before it
                 * was installed — so each is printed whole, as clone prints it */
                output_gap(out, OUTPUT_NORMAL);
                output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
                return;  /* best-effort */
            }
            output_success(
                out, OUTPUT_VERBOSE, "Adopted repository epoch from remote"
            );

            /* The run's crypto handles were bound to the epoch at dispatch; the
             * fetch moved that authority mid-command, so re-bind — the same duty
             * sync discharges for Git by rebuilding the manifest after the pulls.
             * NULL-safe, and on two of the three findings that is what it is: a
             * local ref yielding no epoch fails the dispatch load, so a run that
             * reaches them has encryption off and no keymgr to re-bind. What
             * the old epoch's session file holds is not this run's to remove:
             * the file is named by the epoch, and a checkout still on that epoch
             * is the one entitled to read it. */
            keymgr_rekey(keymgr, &fetched);
            return;
        }
    }
}

/**
 * The workspace guard: what a pull of the run's scope puts at risk, counted and
 * said
 *
 * The load and its flush, the count over the diverged items the scope accepts,
 * and the report: strict_mode's refusal, the warning the consent is asked beneath
 * (cmd_sync), or the notes of what blocks nothing. Unforced runs alone: --force
 * syncs over whatever the workspace holds, and loads none.
 *
 * @param ctx Dispatch context (must not be NULL): the store, the view ahead of
 *            the Git phase, and the arena the workspace lives in
 * @param scope The run's scope (must not be NULL)
 * @param guard What the guard found (must not be NULL; zero where it refuses)
 * @return Error or NULL on success: the load's or the flush's, or strict_mode's
 *         refusal
 */
static error_t sync_guard(const dotta_ctx_t *ctx, const scope_t *scope, sync_guard_t *guard) {
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    *guard = (sync_guard_t){ 0 };

    /* Orphans stay off — a Git probe per profile for items only the settle (apply's
     * cleanup) and status's orphan sections read; the guard counts the view's
     * rows, and the block after the Git phase diffs two views. */
    workspace_options_t ws_opts = {
        .analyze_orphans   = false,
        .analyze_untracked = config->auto_detect_new_files  /* Respect config */
    };
    workspace_t *ws = NULL;
    error_t err = workspace_load(
        ctx->run.repo, ctx->run.state, config, ctx->run.content_cache, ctx->run.manifest,
        &ws_opts, ctx->arena, &ws
    );
    if (err) return err;

    /* What the load owes the record — its observations, its confirmations, the
     * voids of orders the view took back (core/workspace.h workspace_flush) —
     * the confirmations seeding the fast path for subsequent status/apply calls.
     * The flush keeps the failure of the transaction it takes, so sync's workspace
     * validation reads what the load read whatever the flush met. */
    err = workspace_flush(ws);
    if (err) return err;

    /* Count what stands between this workspace and a clean sync, in the scope
     * the run names: a pull of the named profiles moves nothing of the others',
     * so their divergence is neither at risk nor this run's to send to update
     * (scope_accepts_profile — the filter status's sections apply). The deployed
     * partition is read off the one route table (workspace_item_route — the same
     * table status's sections and update's filter read, so sync cannot route an
     * item a third way), the other states by the state switch beside it. One
     * item, one count. */
    workspace_items_t diverged = workspace_diverged(ws);

    /* The rule the arms below follow: sync blocks on update's work and on the
     * conflicts update refuses and the user must decide; it reports, and never
     * blocks on, what no verb takes by default and what one named verb resolves.
     * A squatted tracked directory is a decision (--force, add --force, remove)
     * and blocks, as dotta's own copy does where the user edited it and Git moved
     * past it, at a rung as anywhere; a rung dotta only passes through that the
     * user squats has one verb and no decision — the same fact that gives it
     * its own status section — and blocks nothing, as dotta's own copy untouched
     * does, apply's; and a child beneath any of them is not an edit a pull can
     * conflict with, so it blocks nothing either. */
    size_t uncommitted_count = 0; /* CAPTURE — update's to commit */
    size_t conflict_count = 0;    /* CONFLICT ∪ KIND — status's Conflicts: no default verb */
    size_t deleted_count = 0;     /* DELETED state — update's to commit */
    size_t untracked_count = 0;   /* UNTRACKED state — update --include-new's */
    size_t unverified_count = 0;  /* UNVERIFIABLE, UNSCANNED — dotta could not look; blocks nothing */
    size_t squatted_count = 0;    /* KIND_DERIVED — a rung dotta only passes through; blocks nothing */
    size_t displaced_count = 0;   /* DISPLACED_* — dotta did not look; blocks nothing */

    for (size_t i = 0; i < diverged.count; i++) {
        const workspace_item_t *item = diverged.entries[i];

        if (!scope_accepts_profile(scope, item->profile)) {
            continue;
        }

        switch (item->state) {
            case WORKSPACE_STATE_DEPLOYED:
                switch (workspace_item_route(item)) {
                    case WORKSPACE_ROUTE_DISPLACED_TRACKED:
                    case WORKSPACE_ROUTE_DISPLACED_DERIVED:
                    case WORKSPACE_ROUTE_DISPLACED_STALE:
                    case WORKSPACE_ROUTE_DISPLACED_CONFLICT:
                        /* Beneath a squatter: nothing there was looked at, so
                         * there is no local edit here for a pull to conflict
                         * with — the squatter's own row is the work, and it is
                         * counted under its own arm, or dotta's node at no row
                         * is, the landing's, which this load does not lend. Counted
                         * to be reported, never to block. */
                        displaced_count++;
                        break;

                    case WORKSPACE_ROUTE_UNVERIFIABLE:
                        /* No committable work by definition — the guard is about
                         * local edits a pull would turn into conflicts, and a
                         * path dotta could not read has none to commit. Counted
                         * to be reported, never to block. */
                        unverified_count++;
                        break;

                    case WORKSPACE_ROUTE_CONFLICT:
                    case WORKSPACE_ROUTE_KIND:
                        /* Neither verb's by default (status's Conflicts): both
                         * sides moved — the bytes or the kind, at a rung as
                         * anywhere: dotta's copy the user edited where Git moved
                         * past it is the user's decision — or a kind the copy
                         * cannot commit. update refuses these, so neither the
                         * report's next steps nor the cancel's remedies (cmd_sync)
                         * send them there. */
                        conflict_count++;
                        break;

                    case WORKSPACE_ROUTE_KIND_DERIVED:
                        /* A different kind stands at a directory dotta only passes
                         * through: never planned, so nothing beneath it is dotta's
                         * to lose to a pull, and one named verb resolves it ('dotta
                         * update <dir>'). Counted to be reported, never to
                         * block. */
                        squatted_count++;
                        break;

                    case WORKSPACE_ROUTE_CAPTURE:
                        /* update's work — every capturable divergence, ownership
                         * and encryption included: a policy-violating blob is
                         * uncommitted work exactly here, where a push would publish
                         * it. */
                        uncommitted_count++;
                        break;

                    case WORKSPACE_ROUTE_STALE:
                    case WORKSPACE_ROUTE_REASSIGNED:
                    case WORKSPACE_ROUTE_CLEAN:
                        /* Apply's side or nothing: Git moved past what dotta
                         * last reconciled — the bytes or a claim — and disk did
                         * not, the user's claims riding included, or a pending
                         * reassignment. No local work a pull puts at risk. */
                        break;
                }
                break;

            case WORKSPACE_STATE_DELETED:
                deleted_count++;
                break;

            case WORKSPACE_STATE_UNTRACKED:
                untracked_count++;
                break;

            case WORKSPACE_STATE_UNSCANNED:
                /* Where the scan could not look: nothing there to commit, so no
                 * local edit a pull could turn into a conflict — said as a deployed
                 * path dotta could not look at is, never blocking. The note's
                 * "'dotta status' lists them" holds: sync scans where status
                 * does, under the one switch. */
                unverified_count++;
                break;

            case WORKSPACE_STATE_UNDEPLOYED:
            case WORKSPACE_STATE_ORPHANED:
            case WORKSPACE_STATE_RELEASED:
            case WORKSPACE_STATE_OVERRIDDEN:
            case WORKSPACE_STATE_OBSTRUCTING:
                /* Not sync's concern — handled by apply command. The orphans'
                 * states are never emitted here anyway: they come only from orphan
                 * analysis, which this load switches off. */
                break;
        }
    }

    size_t blocking_count = uncommitted_count + conflict_count +
        deleted_count + untracked_count;

    if (blocking_count > 0) {
        if (config->strict_mode) {
            /* Strict mode: the report says what blocks, and the refusal why.
             * The lines carry status's section vocabulary — one item, one line
             * — and the unverifiable count rides along as an advisory so the
             * paths the analysis could not settle are never silent. A dry run
             * is refused alike: the refusal is what the sync would do, where
             * the non-strict question is consent, which a dry run is owed none
             * of. */
            output_section(out, OUTPUT_NORMAL, "Workspace has uncommitted changes");
            output_gap(out, OUTPUT_NORMAL);

            if (uncommitted_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu uncommitted change%s",
                    uncommitted_count, uncommitted_count == 1 ? "" : "s"
                );
            }
            if (conflict_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu conflict%s",
                    conflict_count, conflict_count == 1 ? "" : "s"
                );
            }
            if (deleted_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu deleted path%s",
                    deleted_count, deleted_count == 1 ? "" : "s"
                );
            }
            if (untracked_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu new untracked file%s",
                    untracked_count, untracked_count == 1 ? "" : "s"
                );
            }
            if (unverified_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu unverifiable path%s",
                    unverified_count, unverified_count == 1 ? "" : "s"
                );
            }
            if (squatted_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu squatted ancestor%s",
                    squatted_count, squatted_count == 1 ? "" : "s"
                );
            }
            if (displaced_count > 0) {
                output_info(
                    out, OUTPUT_NORMAL, "  %zu displaced path%s",
                    displaced_count, displaced_count == 1 ? "" : "s"
                );
            }

            output_gap(out, OUTPUT_NORMAL);
            output_hintline(out, OUTPUT_NORMAL, "Next steps:");
            if (conflict_count > 0) {
                output_hintline(
                    out, OUTPUT_NORMAL,
                    "  Conflicts:      dotta diff, apply --force, add --force, or remove"
                );
            }
            if (uncommitted_count + deleted_count > 0) {
                output_hintline(out, OUTPUT_NORMAL, "  Commit changes: dotta update");
            }
            if (untracked_count > 0) {
                output_hintline(
                    out, OUTPUT_NORMAL,
                    "  New files:      dotta update --include-new"
                );
            }
            output_hintline(out, OUTPUT_NORMAL, "  Synchronize:    dotta sync");

            /* The refusal whole, on stderr, whatever the level: how much blocks,
             * the key that makes it block, and the flag past it — which no step
             * above names, the steps being the report's. */
            return error_create(
                ERR_VALIDATION, "Cannot sync with %zu uncommitted item%s under "
                "strict_mode; --force syncs anyway", blocking_count,
                blocking_count == 1 ? "" : "s"
            );
        }

        /* Non-strict mode: warn, beneath which the user's confirmation of a run
         * that pulls or pushes is asked (cmd_sync)
         *
         * The risk: syncing before committing local changes can turn them into
         * conflicts. If the pull moves a file the user edited, the edit becomes
         * [modified] [stale] — update will not commit over Git's newer content,
         * and no verb takes it by default: the user decides (the cancel's hint
         * names the two flags that do).
         *
         * Safe workflow: update → sync → resolve any divergence explicitly
         */
        output_warning(
            out, OUTPUT_NORMAL, "Workspace has %zu uncommitted change%s",
            blocking_count, blocking_count == 1 ? "" : "s"
        );

        /* Show breakdown in verbose mode */
        if (uncommitted_count > 0) {
            output_info(out, OUTPUT_VERBOSE, "  %zu uncommitted", uncommitted_count);
        }
        if (conflict_count > 0) {
            output_info(
                out, OUTPUT_VERBOSE, "  %zu conflict%s",
                conflict_count, conflict_count == 1 ? "" : "s"
            );
        }
        if (deleted_count > 0) {
            output_info(out, OUTPUT_VERBOSE, "  %zu deleted", deleted_count);
        }
        if (untracked_count > 0) {
            output_info(out, OUTPUT_VERBOSE, "  %zu untracked", untracked_count);
        }
        if (unverified_count > 0) {
            output_info(out, OUTPUT_VERBOSE, "  %zu unverifiable", unverified_count);
        }
        if (squatted_count > 0) {
            output_info(out, OUTPUT_VERBOSE, "  %zu squatted", squatted_count);
        }
        if (displaced_count > 0) {
            output_info(out, OUTPUT_VERBOSE, "  %zu displaced", displaced_count);
        }

        /* Said only where update has work: the risk is to that work, and a block
         * of conflicts alone has none, update refusing every one */
        if (blocking_count > conflict_count) {
            output_info(
                out, OUTPUT_NORMAL, "Syncing before 'update' may lead to conflicts"
            );
        }
    } else {
        /* Nothing blocks, but not every path is settled: say so and proceed.
         * Silence here once hid real divergence — the one route the old fold
         * never counted. A path the analysis could not read no verb resolves;
         * the user must look (status's Unverifiable section carries the way out).
         * A squatted rung dotta only passes through has its one verb, and status's
         * own section names it; a path beneath a squatter waits on the squatter,
         * and status lists both. */
        if (unverified_count > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "Note: %zu path%s could not be verified ('dotta status' lists %s)",
                unverified_count, unverified_count == 1 ? "" : "s",
                unverified_count == 1 ? "it" : "them"
            );
        }
        if (squatted_count > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "Note: %zu squatted ancestor%s — a different kind stands at a "
                "directory dotta only passes through ('dotta status' lists %s)",
                squatted_count, squatted_count == 1 ? "" : "s",
                squatted_count == 1 ? "it" : "them"
            );
        }
        if (displaced_count > 0) {
            output_info(
                out, OUTPUT_NORMAL,
                "Note: %zu path%s not looked at, beneath a squatted directory "
                "('dotta status' lists %s)",
                displaced_count, displaced_count == 1 ? "" : "s",
                displaced_count == 1 ? "it" : "them"
            );
        }
    }

    *guard = (sync_guard_t){ .blocking = blocking_count, .conflicts = conflict_count };
    return NULL;
}

/**
 * Sync command implementation
 */
error_t cmd_sync(const dotta_ctx_t *ctx, const cmd_sync_options_t *opts) {
    CHECK_NULL(ctx);
    CHECK_NULL(opts);

    git_repository *repo = ctx->run.repo;
    state_t *state = ctx->run.state;
    const manifest_t *before = ctx->run.manifest;  /* The view ahead of the Git phase: the dispatcher's */
    const config_t *config = ctx->config;
    output_t *out = ctx->out;

    /* Declare all resources, initialized to NULL. */
    error_t err = NULL;
    manifest_t *after = NULL;                  /* The view after the Git phase */
    scope_t *scope = NULL;
    const char *remote_name = NULL;
    const char *remote_url = NULL;
    transfer_context_t *xfer = NULL;

    /* Build operation scope
     *
     *   scope_enabled  — the persistent enabled set, the CLI filter's bound and
     *                    the Manifest block's attribution.
     *   scope_profiles — sync operation face (fetch / analyze / pull targets).
     */
    scope_inputs_t scope_inputs = {
        .profiles      = opts->profiles,
        .profile_count = opts->profile_count,
    };
    err = scope_build(repo, before, &scope_inputs, ctx->arena, &scope);
    if (err) goto cleanup;

    /* Nothing to sync: refused, in the words that say whether nothing is enabled
     * or no enabled profile has its branch */
    err = scope_require_enabled(state, scope_enabled(scope), ctx->arena);
    if (err) goto cleanup;

    /* Auto-detect remote early — fail fast before expensive workspace load. URL
     * is resolved alongside the name; the credential helper consumes it when
     * transfer_context_create runs further down. */
    err = gitops_resolve_default_remote(
        repo, ctx->arena, &remote_name, &remote_url
    );
    if (err) goto cleanup;

    /* Validate workspace - sync requires clean workspace (no uncommitted changes)
     *
     * Skip entirely when --force is used: the guard's answer is unused, and its
     * load can be expensive (filesystem analysis, directory scanning). Either
     * way the view ahead of the Git phase is `before` — the dispatcher's, which
     * the guard's workspace joins and which --force reads as it is, no disk
     * involved. The block after the Git phase diffs it against the view the pulls
     * produced.
     */
    sync_guard_t guard = { 0 };
    if (!opts->force) {
        err = sync_guard(ctx, scope, &guard);
        if (err) goto cleanup;
    }

    /* Build the hook invocation. Same struct is reused for both pre-sync (here)
     * and post-sync (after the manifest block). The invocation's strings are
     * the command arena's; sync_extras is a stack literal whose lifetime is
     * cmd_sync's frame — covers both fire sites. */
    char *const sync_extras[] = {
        arena_str_format(ctx->arena, "DOTTA_REMOTE=%s", remote_name), NULL
    };
    const hook_invocation_t hook_inv = {
        .cmd        = HOOK_CMD_SYNC,
        .profile    = string_array_join(ctx->arena,scope_profiles(scope),  " "),
        .paths      = NULL,
        .path_count = 0,
        .extras     = sync_extras,
        .dry_run    = opts->dry_run,
    };

    /* The pre-sync hook, over the run the guard decided — strict_mode's refusal
     * fired none — and before the consent the guard owes; a dry run's too, told
     * so (DOTTA_DRY_RUN=1). It gates the network, so sync decides twice: what
     * to pull and push is the Git phase's, after the fetch that follows the hook,
     * and the one question a force push or a reset owes is asked there, beneath
     * the preview and before any profile acts. */
    err = hook_fire_pre(config, out, &hook_inv);
    if (err) goto cleanup;

    if (guard.blocking > 0 && !opts->dry_run) {
        /* The user's consent, after the hook, defaulting to no: a terminal's
         * answer or a pipe's — the question discards nothing, so any stdin answers
         * it. A dry run, pulling and pushing nothing, owes none: the guard's
         * report is its preview. Declined or unanswered, the run stops before
         * the Git phase and says what to do first: declined is the user's word,
         * a cancel and no failure; no answer, nobody declined, and the run is
         * refused as strict mode refuses it, naming the flag that syncs anyway. */
        const output_answer_t answer = output_ask(out, false, "Continue anyway?");
        if (answer != OUTPUT_ANSWER_YES) {
            output_gap(out, OUTPUT_NORMAL);
            if (answer == OUTPUT_ANSWER_NO) {
                output_info(out, OUTPUT_NORMAL, "Cancelled");
            }
            if (guard.conflicts > 0) {
                /* The status Conflicts header's remedies, a kind both sides moved
                 * among the conflicts: add keeps disk's only where the kind
                 * matches, and apply --force replaces a directory only with all
                 * it holds. Update refuses every one of them, so its clause rides
                 * only where it has work beside them */
                output_hint(
                    out, OUTPUT_NORMAL,
                    "Resolve conflicts first: 'dotta diff' compares; 'dotta apply "
                    "--force' keeps Git's (a directory only if all dotta's), 'dotta add "
                    "--force' keeps disk's when the kind matches, 'dotta remove' "
                    "untracks%s",
                    guard.blocking > guard.conflicts
                        ? "; 'dotta update' commits the rest" : ""
                );
            } else {
                output_hint(
                    out, OUTPUT_NORMAL,
                    "Run 'dotta update' first to commit local changes"
                );
            }
            if (answer == OUTPUT_ANSWER_NONE) {
                err = error_create(
                    ERR_VALIDATION, "Cannot sync with %zu uncommitted item%s without a "
                    "confirmation, and none was read; --force syncs anyway",
                    guard.blocking, guard.blocking == 1 ? "" : "s"
                );
            }
            goto cleanup;  /* err is NULL for a decline: a cancel, not an error */
        }

        /* Confirmed: proceed, a verbose line of its own beneath the question */
        output_gap(out, OUTPUT_VERBOSE);
        output_info(out, OUTPUT_VERBOSE, "Proceeding with uncommitted changes");
    }

    /* Create transfer context for progress reporting. URL was resolved alongside
     * the remote name above; it feeds the credential helper here */
    transfer_options_t xfer_opts = {
        .output             = out,
        .url                = remote_url,
        .ephemeral_progress = true,
    };
    xfer = transfer_context_create(&xfer_opts);

    /* Reconcile the repository epoch with the remote. Placed before the fetch
     * so the divergence's census cannot see pulled remote ciphertext. */
    sync_reconcile_epoch(ctx, remote_name, xfer, opts);

    err = sync_fetch(ctx, remote_name, scope, xfer);
    if (err) goto cleanup;

    /* The run, decided whole before any profile acts: each profile's state against
     * the remote, then its verdict and what the user's word withholds of it —
     * read by the preview, the question, the act and the receipt, none of which
     * decides again. The decision answers the one fact the gate reads: the act
     * the run discards commits by, a force push or a reset, where one stands. */
    sync_rows_t rows = sync_analyze(ctx->arena, repo, remote_name, scope);
    const sync_verdict_t discarding = sync_decide(&rows, config, opts);

    /* The confirmation that act owes, where the configuration asks one and the
     * run is no dry run, is a person's at a terminal (base/output.h
     * output_ask_destructive): off one the run is refused here, at the decision,
     * before the preview, and nothing acts. sync's --force is the guard's, and
     * answers nothing here. */
    const bool asks = config->confirm_destructive && !opts->dry_run &&
        discarding != SYNC_VERDICT_NONE;
    if (asks && !isatty(STDIN_FILENO)) {
        err = sync_refusal(ctx->arena, &rows, discarding, "which only a terminal gives");
        goto cleanup;
    }

    /* The preview: a dry run's block, or the question's preamble where one is
     * asked; a run that asks nothing previews nothing it then does at once, and
     * its receipt says what it did */
    if (opts->dry_run || asks) sync_print_preview(out, remote_name, &rows);

    /* A dry run ends here, its preview shown, and nothing pulled or pushed: the
     * fetch moved the remote-tracking refs alone. The answer still stands — a
     * profile the analysis could not read is a question the dry run failed to
     * answer, not a profile it found no work for. */
    if (opts->dry_run) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(out, OUTPUT_NORMAL, "Dry run: nothing was pulled or pushed");
        err = sync_failure(ctx->arena, &rows);
        goto cleanup;
    }

    /* The question, beneath the preview and before any profile acts. Declined
     * is the user's word: the whole run cancelled, and no failure. Unanswered —
     * the terminal's input ended — nobody declined, and the run is refused, naming
     * the key that answers in advance. */
    if (asks) {
        switch (sync_ask(out, ctx->arena, &rows, discarding)) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
                output_gap(out, OUTPUT_NORMAL);
                output_info(out, OUTPUT_NORMAL, "Cancelled");
                goto cleanup;  /* err is NULL: a cancel is not a failure */
            case OUTPUT_ANSWER_NONE:
                err = sync_refusal(ctx->arena, &rows, discarding, "and none was read");
                goto cleanup;
        }
    }

    /* The act: every verdict carried out, and nothing said. Git only — no state
     * is written, so the write lock is never held across network IO. Nothing
     * catches up afterwards either: the view is computed, and the block that
     * follows only reports what the act did to it. */
    err = sync_execute(repo, remote_name, &rows, xfer);

    /* The receipt, once every act is done, a row for every profile — a run a
     * failed rollback stopped among them, which then ends in that error — and
     * at verbose the wire beneath it, Git's tally of what the lines above say
     * moved */
    sync_print_receipt(out, remote_name, &rows);
    if (err) goto cleanup;
    transfer_summarize(xfer, out, OUTPUT_VERBOSE);

    /* Manifest block — the view after the Git phase, diffed against the view
     * before it. A true delta in both modes: a local external commit that predates
     * the sync is in `before` and `after` alike and is reported by its results
     * (status's [stale], [released]), not here; what the block names is what
     * the pulls and resolutions above did to the view. A commit the pre-sync
     * hook makes is in `after` alone, and reads as the pull's: the hook runs
     * over a run decided before it, and nothing reads again across it. Sync writes
     * no state.
     *
     * Attribution is per enabled profile — scope_enabled, never the -p narrowed
     * scope_profiles: precedence runs across the whole enabled set, which is
     * what both views are built over (the state's rows: nothing in sync writes
     * enabled_profiles, but where its flush takes the lock it reads them again,
     * so a profile change another process commits in between reaches the view
     * after alone and reads as the pull's — a residue, accepted; a missing branch
     * contributes nothing to either, said by status's and apply's health off
     * the view, core/manifest.h manifest_missing). A path p lost to q is p's
     * reassignment and q's claim; a path that moved between two pulled profiles
     * is one reassignment, never a transient release; and a claim of p's that a
     * blob the pull brought now stands above is p's overridden, never a release
     * either: its copy is that blob's landing's, which clears it.
     *
     * Sync does not deploy, nor settle what a pull let go: apply's divergence
     * analysis does both, which is what the hint closing the report points at.
     *
     * A failed build is not sync's failure — every Git ref already moved and
     * stands — and its message carries the repair (a tree that will not load,
     * metadata that will not parse): warn with it and carry on. A pulled custom/
     * claim this machine cannot place does not fail the build, nor does a pulled
     * claim the profile's own tree contradicts; the health notices after the
     * block are their signal. */
    const string_array_t *enabled = scope_enabled(scope);

    err = manifest_build(repo, state, ctx->arena, &after);
    if (err) {
        output_warning(out, OUTPUT_NORMAL, "%s", error_line(err));
    } else {
        state_record_t *records = NULL;
        size_t record_count = 0;
        err = state_records(state, ctx->arena, &records, &record_count);
        if (err) goto cleanup;

        manifest_diff_stats_t *stats = arena_calloc(
            ctx->arena, enabled->count, sizeof(*stats)
        );

        manifest_diff(before, after, records, record_count, enabled, stats);

        bool manifest_changed = false;  /* The block's header, said at its first line */
        for (size_t i = 0; i < enabled->count; i++) {
            const manifest_diff_stats_t *s = &stats[i];
            if (s->added + s->updated + s->reassigned + s->overridden + s->orphaned == 0) {
                continue;
            }

            if (!manifest_changed) {
                output_section(out, OUTPUT_NORMAL, "Manifest");
                manifest_changed = true;
            }

            /* One line per profile, its non-zero counts in the diff's order:
             * what the pull added and updated, what passed to another profile,
             * what another's blob stands over, what left. A departure here is a
             * Git-side removal, so an orphan it leaves is one apply releases
             * (the record retires, the copy stays) — a file Git let go, a directory
             * holding what no apply removes — save where the orphan analysis
             * decides otherwise (core/workspace.c workspace_analyze_orphans),
             * each counted released all the same (stated): a copy already gone,
             * reclaimed; dotta's node above a row the view after stands, which
             * the landing beneath it replaces; a copy beneath a blob it stands,
             * which that blob's landing clears; a copy the user ordered pruned,
             * where it can be measured; and a directory dotta created that the
             * run empties, which apply prunes, Git never asked of a directory.
             * A departure with no record has no filesystem effect and asks nothing
             * of the user, so it is not counted. */
            output_print(out, OUTPUT_NORMAL, "  {cyan}%s{reset}:", s->profile);
            const char *sep = " ";
            if (s->added > 0) {
                output_print(out, OUTPUT_NORMAL, "%s%zu added", sep, s->added);
                sep = ", ";
            }
            if (s->updated > 0) {
                output_print(out, OUTPUT_NORMAL, "%s%zu updated", sep, s->updated);
                sep = ", ";
            }
            if (s->reassigned > 0) {
                output_print(
                    out, OUTPUT_NORMAL, "%s%zu reassigned", sep, s->reassigned
                );
                sep = ", ";
            }
            if (s->overridden > 0) {
                output_print(
                    out, OUTPUT_NORMAL, "%s%zu overridden", sep, s->overridden
                );
                sep = ", ";
            }
            if (s->orphaned > 0) {
                output_print(out, OUTPUT_NORMAL, "%s%zu released", sep, s->orphaned);
            }
            output_endline(out, OUTPUT_NORMAL);
        }

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
         * profile and in no row — a sync's merge composes one from two machines'
         * ordinary edits and refuses none, and brings a pair of names two of
         * this machine's labels place on one chain — so the import is where it
         * is first named. The remedy turns on the pair's shape, which status -v
         * prints, as apply's section says. */
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

        /* The hint states a fact about the record, not about this sync: the record
         * owes apply work against the view the Git phase produced (core/workspace.h
         * workspace_pending), whatever began it — this pull, an earlier one
         * reviewed with status instead of apply, a scope change, a revert — and
         * whatever the work is, so its words name apply's aim and no outcome.
         * The block is a delta and prints once; the hint prints for as long as
         * the work stands, and a pull that moved only the way to a claim — a
         * derived directory's mode — moves neither. */
        if (workspace_pending(after, records, record_count)) {
            output_gap(out, OUTPUT_NORMAL);
            output_hint(
                out, OUTPUT_NORMAL,
                "Run 'dotta apply' to bring the workspace in line with the enabled profiles"
            );
        }
    }

    /* Post-sync fires once the report is done — the receipt, the manifest block
     * and its hint; a failed build was warned above and is not a reason to skip
     * it. Nor is a profile that failed: the pushes and pulls that did land are
     * real, and the hook's subject is the world sync leaves behind, not what
     * sync returns. */
    hook_fire_post(config, out, &hook_inv);

    /* The report is printed; the return value is what the caller reads. */
    err = sync_failure(ctx->arena, &rows);

cleanup:
    /* The one handle the run holds: the transfer, whose close commits the
     * credential decision (sys/transfer.h). state is borrowed from the dispatcher
     * and sync opens no transaction of its own (the flush scopes its own; nothing
     * else writes), and the rows are the command arena's. */
    transfer_context_free(xfer);

    return err;
}

/* ══════════════════════════════════════════════════════════════════
 * Spec-engine integration
 * ══════════════════════════════════════════════════════════════════ */

/**
 * The divergence strategy the line names, judged and converted in the
 * configuration's words (utils/config.h config_parse_strategy): a word the
 * vocabulary does not know refuses the line before the store opens. The refusal
 * is the vocabulary's own, unwrapped — --diverged is the one place a strategy
 * word stands on the line, and the word is quoted in it.
 */
static error_t sync_post_parse(
    void *opts_v, arena_t *arena, const args_command_t *cmd
) {
    (void) arena;
    (void) cmd;
    cmd_sync_options_t *o = opts_v;

    return o->diverged ? config_parse_strategy(o->diverged, &o->diverged_strategy) : NULL;
}

/**
 * What can stand at the cursor: an enabled profile, by -p or bare; for --diverged,
 * a strategy.
 */
static args_want_t sync_complete(
    const void *ctx_v, const void *opts_v, const args_completion_t *at, FILE *out
) {
    (void) opts_v;
    const dotta_ctx_t *ctx = ctx_v;

    if (ARGS_VALUE_IS(at, cmd_sync_options_t, diverged)) {
        for (size_t i = 0; i < CONFIG_STRATEGY_COUNT; i++) {
            fprintf(
                out, "%s\t%s\n",
                config_strategies[i].name, config_strategies[i].summary
            );
        }
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
        cmd_sync_options_t,profiles,     profile_count,
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
        "Pull only; skip push"
    ),
    ARGS_FLAG(
        "no-pull",
        cmd_sync_options_t,no_pull,
        "Push only; skip pull"
    ),
    ARGS_FLAG(
        "f force",
        cmd_sync_options_t,force,
        "Sync even with uncommitted local changes"
    ),
    ARGS_STRING(
        "diverged",        "<strategy>",
        cmd_sync_options_t,diverged,
        "Diverged-branch strategy (see notes)"
    ),
    ARGS_FLAG_SET(
        "v verbose",
        cmd_sync_options_t,verbosity,    DOTTA_VERBOSITY_VERBOSE,
        "Verbose output"
    ),
    /* Bare profile positionals funnel into the same APPEND field. */
    ARGS_POSITIONAL_ANY(
        cmd_sync_options_t,profiles,     profile_count
    ),
    ARGS_END,
};

const args_command_t spec_sync = {
    .name         = "sync",
    .summary      = "Synchronize profiles with remote repository",
    .usage        = "%s sync [options] [profile]...",
    .description  =
        "Fetch, analyze, and reconcile enabled profiles with their\n"
        "remote counterparts. Requires a clean workspace; run '%s\n"
        "update' to commit pending filesystem changes first.\n",
    .notes        =
        "Diverged Strategies:\n"
        "  warn          Report the divergence, resolve by hand (the default)\n"
        "  rebase        Rebase local commits onto the remote\n"
        "  merge         Merge the remote into the local branch\n"
        "  ours          Keep local, force-push over the remote\n"
        "  theirs        Keep remote, reset the local branch\n"
        "\n"
        "  The strategy is [sync] diverged_strategy's, or --diverged's for one\n"
        "  run. ours and theirs act on a branch that is only behind or only\n"
        "  ahead as well: ours force-pushes over the newer remote commits, and\n"
        "  theirs resets the local ones away.\n",
    .examples     =
        "  %s sync                    # All enabled profiles\n"
        "  %s sync global             # Single profile\n"
        "  %s sync global darwin      # Multiple profiles\n"
        "  %s sync -n                 # Preview without pulling or pushing\n"
        "  %s sync -f                 # Bypass clean-workspace check\n"
        "  %s sync --no-pull          # Push only\n"
        "  %s sync --diverged rebase  # Override divergence strategy\n",
    .epilogue     =
        "See also:\n"
        "  %s update          # Commit local changes first\n"
        "  %s status --remote # Inspect remote state before syncing\n",
    .opts_size    = sizeof(cmd_sync_options_t),
    .opts         = sync_opts,
    .post_parse   = sync_post_parse,
    .complete     = sync_complete,
    .payload      = &(const dotta_needs_t){
        .repo     = DOTTA_REPO_OPEN,
        .state    = DOTTA_STATE_READ,
        .crypto   = DOTTA_CRYPTO_CACHED,
        .manifest = true,
    },
    .dispatch     = sync_dispatch,
};
