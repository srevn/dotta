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
 * Per-profile sync result
 *
 * The profile's state against the remote, and the failure the run met for it. A
 * row fails by its error, whichever phase met it: said on the profile's line
 * where it is met — the analyze phase's read back by the push phase and the dry
 * run — and counted by sync_failure. A row with no error whose state is up-to-date
 * is one the run had nothing to do for, its line verbose's, counted at normal
 * by cmd_sync; every other row's line says what the run did with it.
 */
typedef struct {
    const char *profile;           /* The scope's own name, borrowed */
    upstream_state_t state;
    size_t ahead;
    size_t behind;
    error_t error;                 /* The failure's cause, borrowed; NULL where the run met none */
} profile_sync_result_t;

/**
 * The results: one row per profile in the sync scope, in its order — a value of
 * the command arena, as its rows are
 */
typedef struct {
    profile_sync_result_t *profiles;
    size_t profile_count;
} sync_results_t;

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
 * Fast-forward a branch to its remote-tracking ref, and nothing else; *updated
 * says whether it moved
 */
static error_t pull_branch_ff(
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
 * Phase 1: Fetch profiles in sync scope from remote
 *
 * Operates on the scope's profiles (scope_profiles): fetching is driven by what
 * the user asked for. `dotta sync -p work` fetches only `work`, not every enabled
 * profile. Precedence-adjacent work (push phase) still uses the full enabled
 * set — different role, different accessor.
 */
static error_t sync_fetch_phase(
    const dotta_ctx_t *ctx,
    const char *remote_name,
    const scope_t *scope,
    transfer_context_t *xfer
) {
    CHECK_NULL(ctx);
    CHECK_NULL(remote_name);
    CHECK_NULL(scope);

    git_repository *repo = ctx->run.repo;
    output_t *out = ctx->out;
    const string_array_t *profiles = scope_profiles(scope);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int rc = git_remote_lookup(&remote, repo, remote_name);
    if (rc == GIT_ENOTFOUND) {
        return error_create(ERR_NOT_FOUND, "No remote '%s' configured", remote_name);
    } else if (rc < 0) {
        return error_git(rc, "Cannot fetch from remote '%s'", remote_name);
    }
    git_remote_free(remote);

    /* Ephemeral fetch progress — shown while fetching, cleared after. On TTY:
     * transfer progress overwrites via \r, then line cleared entirely. On pipe:
     * falls back to persistent line with newline. */
    bool ephemeral = output_is_tty(out);
    output_print(
        out, OUTPUT_NORMAL, "Fetching from '%s'...",
        remote_name
    );
    fflush(out->stream);

    /* The branches to ask for: the profiles the remote has been seen to hold —
     * a remote-tracking ref stands for each — so a profile only this machine
     * has (never pushed) is not asked for. Whether the ref stands is Git's answer
     * or Git's error (gitops_reference_exists): a ref this run cannot read is
     * not "never pushed", and read as that it left the profile out of the fetch
     * without a word. */
    string_array_t branch_names;
    string_array_init(&branch_names, ctx->arena, 0);

    error_t err = NULL;
    for (size_t i = 0; i < profiles->count; i++) {
        char remote_refname[DOTTA_REFNAME_MAX];
        err = gitops_remote_branch_refname(
            remote_refname, sizeof(remote_refname), remote_name, profiles->entries[i]
        );
        if (err) break;

        bool tracked = false;
        err = gitops_reference_exists(repo, remote_refname, &tracked);
        if (err) break;

        if (tracked) {
            string_array_push(&branch_names, profiles->entries[i]);
        }
    }
    if (err) {
        if (ephemeral) {
            output_clear_line(out);
        } else {
            output_endline(out, OUTPUT_NORMAL);
        }
        return err;
    }

    /* Skip fetch entirely if no profiles have remote tracking refs */
    if (branch_names.count == 0) {
        if (ephemeral) {
            output_clear_line(out);
        } else {
            output_endline(out, OUTPUT_NORMAL);
        }
        return NULL;
    }

    /* Perform batched fetch - single network operation for all branches */
    err = gitops_fetch_branches(repo, remote_name, &branch_names, xfer);

    /* The announce line ends here. Progress drawn over it ended with its op
     * (sys/transfer.h transfer_op_end), whichever way the op went, so what can
     * stand is the announce alone — an up-to-date fetch draws nothing over it:
     * cleared on a terminal, ended on a pipe. */
    if (ephemeral) {
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
 * Phase 2: the results — one row per profile in the sync scope, in its order,
 * each seeded with its branch's state against the remote
 *
 * The table is made here, in `arena`, as scope_profiles(scope) orders it — the
 * profiles sync_fetch_phase fetched: analyze only what the user asked for. A
 * row names its profile by the scope's own string. A profile it cannot analyze
 * fails in its own row, by its error, and the push phase's skip line and the
 * dry run read that cause back; a later phase says its own failure where it
 * happens.
 */
static sync_results_t sync_analyze_phase(
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
    sync_results_t results = {
        .profiles      = arena_calloc(arena, profiles->count, sizeof(*results.profiles)),
        .profile_count = profiles->count,
    };

    for (size_t i = 0; i < profiles->count; i++) {
        profile_sync_result_t *result = &results.profiles[i];

        result->profile = profiles->entries[i];

        /* Analyze state */
        upstream_info_t info;
        error_t err = upstream_analyze_profile(
            repo, remote_name, profiles->entries[i], &info
        );

        if (err) {
            result->error = err;
            continue;
        }

        result->state = info.state;
        result->ahead = info.ahead;
        result->behind = info.behind;
    }

    return results;
}

/**
 * Roll a resolution back to the head the branch stood at before it
 *
 * A rollback that succeeds is the profile's row. One that fails leaves the branch
 * where the resolution put it and ends the run, its error told once, by the run's
 * renderer.
 */
static error_t sync_rollback(
    resolve_context_t *resolve,
    const char *profile,
    const char *failure_reason,
    output_t *out
) {
    error_t err = resolve_rollback(resolve);
    if (err) {
        /* The error names the head, the one fact a repair starts from: whole,
         * as git's own ref refusals spell an id (lib/git/refs/packed-backend.c,
         * oid_to_hex), where an abbreviation could name two commits. */
        char oid_str[GIT_OID_SHA1_HEXSIZE + 1];
        git_oid_tostr(oid_str, sizeof(oid_str), &resolve->saved_oid);
        return error_wrap(
            err, "Failed to roll back branch '%s' to %s, its head before the sync, "
            "after the %s", profile, oid_str, failure_reason
        );
    }

    output_info(out, OUTPUT_NORMAL, "    ↺ Rolled back to original state");

    return NULL;
}

/**
 * Handle UPSTREAM_REMOTE_AHEAD: auto-pull (fast-forward) or warn
 */
static void handle_remote_ahead(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    bool auto_pull,
    bool no_pull
) {
    if (!auto_pull) {
        /* Just warn - don't auto-pull */
        output_colored(
            out, OUTPUT_NORMAL, upstream_state_color(result->state),
            "  %s %s: remote has %zu new commit%s\n",
            upstream_state_symbol(result->state),
            result->profile, result->behind, result->behind == 1 ? "" : "s"
        );

        if (no_pull) {
            output_hint(
                out, OUTPUT_NORMAL,
                "    Pull skipped (--no-pull)"
            );
        } else {
            output_hint(
                out, OUTPUT_NORMAL,
                "    Enable 'auto_pull' for automatic pull during sync"
            );
        }
        return;
    }

    /* Auto-pull when safe (fast-forward only) */
    output_info(
        out, OUTPUT_VERBOSE, "  Pulling %s (%zu commit%s behind)...",
        result->profile, result->behind, result->behind == 1 ? "" : "s"
    );

    /* A pull that fails is the profile's row, its cause as it stands: the
     * fast-forward names its act and its branch (pull_branch_ff) */
    bool pulled = false;
    error_t err = pull_branch_ff(repo, remote_name, result->profile, &pulled);
    if (err) {
        output_print(
            out, OUTPUT_NORMAL,
            "  {red}✗{reset} {red}%s{reset}: %s\n",
            result->profile, error_line(err)
        );
        result->error = err;
        return;
    }

    if (!pulled) {
        /* Race: analyze saw REMOTE_AHEAD but FF found nothing new (we caught up
         * between phases). Reclassify to reflect reality: the row is up to date,
         * its line verbose's, and cmd_sync counts it with the others. */
        result->state = UPSTREAM_UP_TO_DATE;
        output_colored(
            out, OUTPUT_VERBOSE, upstream_state_color(result->state),
            "  %s %s: already up-to-date\n",
            upstream_state_symbol(result->state), result->profile
        );
        return;
    }

    /* Pull succeeded. What the pull did to the view is reported by cmd_sync's
     * manifest block, once, after every profile's Git work. */
    output_print(
        out, OUTPUT_NORMAL,
        "  {green}✓{reset} {green}%s{reset}: pulled %zu commit%s\n",
        result->profile, result->behind, result->behind == 1 ? "" : "s"
    );
}

/**
 * Resolve divergence via rebase or merge, then push
 *
 * Unified handler for SYNC_STRATEGY_REBASE and SYNC_STRATEGY_MERGE (structurally
 * identical — only the strategy enum and log strings differ).
 *
 * Returns critical error only on rollback failure (caller must propagate). Every
 * other failure is the row's error, and returns NULL.
 */
static error_t resolve_and_push_divergence(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    resolve_strategy_t strategy,
    const char *strategy_name,
    transfer_context_t *xfer,
    bool no_push
) {
    const char *past_desc = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "rebased onto remote" : "merged with remote";
    const char *push_desc = (strategy == RESOLVE_STRATEGY_REBASE)
        ? "rebased commits" : "merge commit";

    output_info(
        out, OUTPUT_NORMAL,
        "    Resolving with '%s' strategy...",
        strategy_name
    );

    /* Initialize divergence context (saves current state for rollback). A step
     * that fails is a row of its own beneath the announce above, its cause as
     * it stands: each names its act and its branch (sys/resolve.h, sys/gitops.h) */
    resolve_context_t resolve;
    error_t err = resolve_init(
        &resolve, repo, remote_name, result->profile, strategy
    );
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        result->error = err;
        return NULL;
    }

    /* Perform in-memory resolution (never modifies HEAD) */
    err = resolve_execute(&resolve, NULL);
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        result->error = err;
        return NULL;
    }

    /* Verify resolution */
    size_t ahead = 0;
    err = resolve_verify(&resolve, &ahead, NULL);
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        result->error = err;

        char reason[64];
        snprintf(
            reason, sizeof(reason), "%s verification failure", strategy_name
        );
        return sync_rollback(&resolve, result->profile, reason, out);
    }

    output_print(
        out, OUTPUT_NORMAL,
        "    {green}✓{reset} Successfully %s (%zu commit%s to push)\n",
        past_desc, ahead, ahead == 1 ? "" : "s"
    );

    if (no_push) {
        /* Resolved locally all the same: the next sync sees LOCAL_AHEAD */
        output_info(out, OUTPUT_NORMAL, "    Push skipped (--no-push)");
    } else {
        /* Push resolved commits */
        err = gitops_push_branch(repo, remote_name, result->profile, xfer);
        if (err) {
            output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
            result->error = err;

            output_info(
                out, OUTPUT_NORMAL,
                "    ↺ Rolling back %s (push failed)...",
                strategy_name
            );
            return sync_rollback(
                &resolve, result->profile, "push failure", out
            );
        }

        output_print(
            out, OUTPUT_NORMAL,
            "    {green}✓{reset} Pushed %s\n",
            push_desc
        );
    }

    return NULL;
}

/**
 * Handle SYNC_STRATEGY_OURS: force push local branch to remote
 */
static void handle_diverged_ours(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    bool confirm_destructive,
    transfer_context_t *xfer,
    bool no_push
) {
    output_info(
        out, OUTPUT_NORMAL, "    Resolving with '%s' strategy (force push)...",
        config_strategies[SYNC_STRATEGY_OURS].name
    );

    if (no_push) {
        output_info(out, OUTPUT_NORMAL, "    Force push skipped (--no-push)");
        return;
    }

    /* The user's confirmation for a destructive operation, where the configuration
     * asks for one. Declined leaves the divergence standing, said once; unanswered
     * — off a terminal, where a destructive question is never asked — is this
     * profile's failure, its row naming the key that answers in advance, and
     * nobody declined. */
    if (confirm_destructive) {
        switch (output_ask_destructive(
            out, "Force push '%s' over the remote's commits?", result->profile
            )) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
                output_info(out, OUTPUT_NORMAL, "    Operation cancelled by user");
                return;
            case OUTPUT_ANSWER_NONE: {
                error_t err = error_create(
                    ERR_VALIDATION, "Cannot force push '%s' without a confirmation, which "
                    "only a terminal gives; confirm_destructive = false pushes without "
                    "asking", result->profile
                );
                output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
                result->error = err;
                return;
            }
        }
    }

    /* Force push local to remote (local branch stays unchanged) */
    error_t err = gitops_force_push_branch(repo, remote_name, result->profile, xfer);
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        result->error = err;
        return;
    }

    output_print(
        out, OUTPUT_NORMAL,
        "    {green}✓{reset} Force pushed to remote (remote commits discarded)\n"
    );
}

/**
 * Handle SYNC_STRATEGY_THEIRS: reset local branch to remote
 */
static void handle_diverged_theirs(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    bool confirm_destructive
) {
    output_info(
        out, OUTPUT_NORMAL,
        "    Resolving with '%s' strategy (reset to remote)...",
        config_strategies[SYNC_STRATEGY_THEIRS].name
    );

    /* The user's confirmation, as the force push asks it (handle_diverged_ours) */
    if (confirm_destructive) {
        switch (output_ask_destructive(
            out, "Reset '%s' to the remote, discarding its local commits?", result->profile
            )) {
            case OUTPUT_ANSWER_YES:
                break;
            case OUTPUT_ANSWER_NO:
                output_info(out, OUTPUT_NORMAL, "    Operation cancelled by user");
                return;
            case OUTPUT_ANSWER_NONE: {
                error_t err = error_create(
                    ERR_VALIDATION, "Cannot reset '%s' to the remote without a "
                    "confirmation, which only a terminal gives; confirm_destructive = false "
                    "resets without asking", result->profile
                );
                output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
                result->error = err;
                return;
            }
        }
    }

    /* Initialize divergence context (saves current state for rollback) */
    resolve_context_t resolve;
    error_t err = resolve_init(
        &resolve, repo, remote_name, result->profile, RESOLVE_STRATEGY_THEIRS
    );
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        result->error = err;
        return;
    }

    /* Resolve divergence (resets local branch to remote) */
    err = resolve_execute(&resolve, NULL);
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        result->error = err;
        return;
    }

    /* Verify reset succeeded
     *
     * No rollback on failure — theirs strategy already reset the branch to the
     * desired state. Rolling back would undo what the user requested.
     */
    err = resolve_verify(&resolve, NULL, NULL);
    if (err) {
        output_print(out, OUTPUT_NORMAL, "    {red}✗{reset} %s\n", error_line(err));
        output_print(
            out, OUTPUT_NORMAL,
            "    {yellow}⚠{reset} Local branch was reset but verification failed\n"
        );
        result->error = err;
        return;
    }

    output_print(
        out, OUTPUT_NORMAL,
        "    {green}✓{reset} Reset to remote (local commits discarded)\n"
    );
}

/**
 * Handle UPSTREAM_DIVERGED: dispatch based on configured strategy
 *
 * Returns critical error only on rollback failure (from rebase/merge).
 */
static error_t handle_diverged(
    git_repository *repo,
    const char *remote_name,
    profile_sync_result_t *result,
    output_t *out,
    sync_strategy_t strategy,
    transfer_context_t *xfer,
    bool confirm_destructive,
    bool no_push
) {
    output_print(
        out, OUTPUT_NORMAL,
        "  {yellow}⚠{reset} {red}%s{reset}: diverged (%zu local, %zu remote commits)\n",
        result->profile, result->ahead, result->behind
    );

    switch (strategy) {
        case SYNC_STRATEGY_WARN: {
            /* The strategies that resolve, each in the phrase completion shows
             * for it: the vocabulary's rows, read, not spelled again here. */
            output_hint(
                out, OUTPUT_NORMAL,
                "    Use --diverged=<strategy> or set diverged_strategy in config:"
            );
            for (size_t s = 0; s < CONFIG_STRATEGY_COUNT; s++) {
                if (s != SYNC_STRATEGY_WARN) {
                    output_hintline(
                        out, OUTPUT_NORMAL, "      %s: %s",
                        config_strategies[s].name, config_strategies[s].summary
                    );
                }
            }
            return NULL;
        }

        case SYNC_STRATEGY_REBASE: {
            return resolve_and_push_divergence(
                repo, remote_name, result, out, RESOLVE_STRATEGY_REBASE,
                config_strategies[strategy].name, xfer, no_push
            );
        }

        case SYNC_STRATEGY_MERGE: {
            return resolve_and_push_divergence(
                repo, remote_name, result, out, RESOLVE_STRATEGY_MERGE,
                config_strategies[strategy].name, xfer, no_push
            );
        }

        case SYNC_STRATEGY_OURS: {
            handle_diverged_ours(
                repo, remote_name, result, out, confirm_destructive,
                xfer, no_push
            );
            return NULL;
        }

        case SYNC_STRATEGY_THEIRS: {
            handle_diverged_theirs(
                repo, remote_name, result, out, confirm_destructive
            );
            return NULL;
        }
    }

    CHECK_ARG(false, "a divergence strategy no enumerator names");
}

/**
 * Phase 3: Sync branches with remote (push/pull/divergence handling)
 *
 * Git only. Every pull, rebase, merge and reset moves a branch HEAD and nothing
 * else; what that did to the view is read off once, for every enabled profile,
 * in cmd_sync's manifest block after this loop returns.
 */
static error_t sync_push_phase(
    git_repository *repo,
    const char *remote_name,
    sync_results_t *results,
    output_t *out,
    bool ephemeral,
    bool auto_pull,
    bool no_pull,
    bool no_push,
    sync_strategy_t diverged_strategy,
    transfer_context_t *xfer,
    bool confirm_destructive
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(results);
    CHECK_NULL(out);

    if (!ephemeral) {
        output_section(out, OUTPUT_NORMAL, "Syncing with remote");
    }

    for (size_t i = 0; i < results->profile_count; i++) {
        profile_sync_result_t *result = &results->profiles[i];

        /* Skip rows that already failed in analyze phase. */
        if (result->error) {
            output_print(
                out, OUTPUT_NORMAL,
                "  {red}✗{reset} {red}%s{reset}: %s\n",
                result->profile, error_line(result->error)
            );
            continue;
        }

        /* Handle based on state */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE: {
                /* Nothing to do, said at verbose: at normal cmd_sync counts these */
                output_colored(
                    out, OUTPUT_VERBOSE, upstream_state_color(result->state),
                    "  %s %s: up-to-date\n",
                    upstream_state_symbol(result->state), result->profile
                );
                break;
            }

            case UPSTREAM_LOCAL_AHEAD: {
                /* theirs: discard the local commits, reset to the remote — a
                 * move a pull makes, so --no-pull withholds it and the profile
                 * stays as it stands, neither reset nor pushed, as --no-push
                 * withholds ours' force push */
                if (diverged_strategy == SYNC_STRATEGY_THEIRS) {
                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: %zu commit%s ahead of remote\n",
                        upstream_state_symbol(result->state),
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    if (no_pull) {
                        output_hint(
                            out, OUTPUT_NORMAL,
                            "    '%s' resolution skipped (--no-pull prevents "
                            "incorporating remote changes)",
                            config_strategies[SYNC_STRATEGY_THEIRS].name
                        );
                    } else {
                        handle_diverged_theirs(
                            repo, remote_name, result, out, confirm_destructive
                        );
                    }
                    break;
                }

                if (no_push) {
                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: %zu commit%s ahead (push skipped: --no-push)\n",
                        upstream_state_symbol(result->state),
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                    break;
                }

                /* Safe to push - local has new commits */
                output_info(
                    out, OUTPUT_VERBOSE, "  Pushing %s (%zu commit%s)...",
                    result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                );

                error_t err = gitops_push_branch(repo, remote_name, result->profile, xfer);
                if (err) {
                    output_print(
                        out, OUTPUT_NORMAL,
                        "  {red}✗{reset} {red}%s{reset}: %s\n",
                        result->profile, error_line(err)
                    );
                    result->error = err;
                } else {
                    output_print(
                        out, OUTPUT_NORMAL,
                        "  {green}✓{reset} {green}%s{reset}: pushed %zu commit%s\n",
                        result->profile, result->ahead, result->ahead == 1 ? "" : "s"
                    );
                }
                break;
            }

            case UPSTREAM_NO_REMOTE: {
                if (no_push) {
                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: local only (push skipped: --no-push)\n",
                        upstream_state_symbol(result->state), result->profile
                    );
                    break;
                }

                /* Remote branch doesn't exist - create it */
                output_info(
                    out, OUTPUT_VERBOSE,
                    "  Creating remote branch %s...",
                    result->profile
                );

                error_t err = gitops_push_branch(repo, remote_name, result->profile, xfer);
                if (err) {
                    output_print(
                        out, OUTPUT_NORMAL,
                        "  {red}✗{reset} {red}%s{reset}: %s\n",
                        result->profile, error_line(err)
                    );
                    result->error = err;
                } else {
                    output_print(
                        out, OUTPUT_NORMAL,
                        "  {green}✓{reset} {green}%s{reset}: created remote branch\n",
                        result->profile
                    );
                }
                break;
            }

            case UPSTREAM_REMOTE_AHEAD: {
                /* ours: force push local, discard remote commits */
                if (diverged_strategy == SYNC_STRATEGY_OURS) {

                    output_colored(
                        out, OUTPUT_NORMAL, upstream_state_color(result->state),
                        "  %s %s: %zu remote commit%s ahead\n",
                        upstream_state_symbol(result->state),
                        result->profile, result->behind, result->behind == 1 ? "" : "s"
                    );
                    output_print(
                        out, OUTPUT_NORMAL,
                        "    {yellow}⚠{reset} Local is behind — "
                        "force push will overwrite newer remote commits\n"
                    );

                    handle_diverged_ours(
                        repo, remote_name, result, out, confirm_destructive, xfer, no_push
                    );
                    break;
                }
                handle_remote_ahead(
                    repo, remote_name, result, out, auto_pull, no_pull
                );
                break;
            }

            case UPSTREAM_DIVERGED: {
                /* --no-pull blocks strategies that incorporate remote changes */
                if (no_pull && diverged_strategy != SYNC_STRATEGY_WARN &&
                    diverged_strategy != SYNC_STRATEGY_OURS) {

                    output_print(
                        out, OUTPUT_NORMAL,
                        "  {yellow}⚠{reset} {red}%s{reset}: diverged "
                        "(%zu local, %zu remote commits)\n",
                        result->profile, result->ahead, result->behind
                    );
                    output_hint(
                        out, OUTPUT_NORMAL,
                        "    '%s' resolution skipped (--no-pull prevents "
                        "incorporating remote changes)",
                        config_strategies[diverged_strategy].name
                    );
                    break;
                }
                error_t err = handle_diverged(
                    repo, remote_name, result, out, diverged_strategy, xfer,
                    confirm_destructive, no_push
                );
                if (err) {
                    return err;  /* Critical rollback failure */
                }
                break;
            }

            case UPSTREAM_NO_LOCAL: {
                output_colored(
                    out, OUTPUT_NORMAL, upstream_state_color(result->state),
                    "  %s %s: no local branch\n",
                    upstream_state_symbol(result->state), result->profile
                );
                break;
            }
        }
    }

    return NULL;
}

/**
 * Render dry-run analysis: per-profile state, then closing banner.
 *
 * Glyph and color flow from upstream_state_symbol / upstream_state_color so the
 * visual stays in lockstep with list/status as those maps evolve. Analyze-phase
 * failures use the failure's glyph (✗), not a state glyph.
 */
static void sync_render_dry_run(
    const sync_results_t *results,
    output_t *out
) {
    output_section(out, OUTPUT_NORMAL, "Dry run analysis");

    for (size_t i = 0; i < results->profile_count; i++) {
        const profile_sync_result_t *r = &results->profiles[i];

        if (r->error) {
            output_print(
                out, OUTPUT_NORMAL, "  {red}✗{reset} %s: %s\n",
                r->profile, error_line(r->error)
            );
            continue;
        }

        const char *glyph = upstream_state_symbol(r->state);
        output_color_t color = upstream_state_color(r->state);

        switch (r->state) {
            case UPSTREAM_UP_TO_DATE:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: up-to-date\n",
                    glyph, r->profile
                );
                break;
            case UPSTREAM_LOCAL_AHEAD:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: %zu commit%s to push\n",
                    glyph, r->profile, r->ahead, r->ahead == 1 ? "" : "s"
                );
                break;
            case UPSTREAM_REMOTE_AHEAD:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: %zu commit%s to pull\n",
                    glyph, r->profile, r->behind, r->behind == 1 ? "" : "s"
                );
                break;
            case UPSTREAM_DIVERGED:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: diverged (%zu local, %zu remote)\n",
                    glyph, r->profile, r->ahead, r->behind
                );
                break;
            case UPSTREAM_NO_REMOTE:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: local only (no remote branch)\n",
                    glyph, r->profile
                );
                break;
            case UPSTREAM_NO_LOCAL:
                output_colored(
                    out, OUTPUT_NORMAL, color,
                    "  %s %s: no local branch\n",
                    glyph, r->profile
                );
                break;
        }
    }

    output_gap(out, OUTPUT_NORMAL);
    output_info(out, OUTPUT_NORMAL, "Dry run: no changes made");
}

/**
 * The run's failure, if it had one — the answer cmd_sync returns.
 *
 * A profile the run tried to reconcile and could not (a row with an error —
 * whatever the phase: analyze, pull, resolve, push) is a broken promise, and
 * only the return value carries that to the caller. The reason was printed on
 * the profile's own row — on stdout, so a redirected sync's report never reads
 * as a clean success — but a shell reads none of it.
 *
 * A profile the run deliberately left alone is not a failure: the caller asked
 * for that (--no-push, --no-pull), the configured strategy did ('warn' on a
 * divergence), or the user declined the prompt. Its own row is its whole report,
 * and `dotta sync && dotta apply` keeps working for everyone who syncs under
 * 'warn'.
 *
 * Pure, and deliberately so: the per-profile errors stay in the rows of `results`
 * that borrow them and are never rethrown, since each was already rendered where
 * it happened. The message carries the one fact no row says — how much of the
 * run the failures were.
 */
static error_t sync_failure(const sync_results_t *results) {
    size_t failed = 0;
    for (size_t i = 0; i < results->profile_count; i++) {
        if (results->profiles[i].error) failed++;
    }

    if (failed == 0) return NULL;

    /* The plural agrees with the total, which is the noun it qualifies: "1 of 2
     * profiles failed", "1 of 1 profile failed". */
    return error_create(
        ERR_GIT, "%zu of %zu profile%s failed to sync",
        failed, results->profile_count,
        results->profile_count == 1 ? "" : "s"
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
        output_warning(
            out, OUTPUT_NORMAL, "Repository epoch left alone: %s", error_line(err)
        );
        return;
    }

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
                out, OUTPUT_NORMAL, "Syncing before 'update' may lead to conflicts."
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

    /* The divergence strategy: the config's, unless --diverged overrides it in
     * the same words — judged by the parse, before the store opened and the
     * pre-sync hook with it (sync_post_parse). */
    sync_strategy_t diverged_strategy = opts->diverged
        ? opts->diverged_strategy : config->diverged_strategy;

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
     * so (DOTTA_DRY_RUN=1). sync decides twice: what to pull and push is the
     * Git phase's, after the fetch that follows the hook, and a diverged profile's
     * ours or theirs question is asked there, profile by profile. */
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
                output_info(out, OUTPUT_NORMAL, "Sync cancelled");
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

        /* Confirmed: proceed */
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

    /* Determine auto_pull setting: CLI --no-pull overrides config */
    bool auto_pull = opts->no_pull ? false : config->auto_pull;

    /* Reconcile the repository epoch with the remote. Placed before the fetch
     * phase so the divergence's census cannot see pulled remote ciphertext. */
    sync_reconcile_epoch(ctx, remote_name, xfer, opts);

    /* Phase 1: Fetch profiles in sync scope from remote */
    err = sync_fetch_phase(ctx, remote_name, scope, xfer);
    if (err) goto cleanup;

    /* Phase 2: Analyze branch states */
    sync_results_t results = sync_analyze_phase(ctx->arena, repo, remote_name, scope);

    /* Dry run: display analysis and exit without executing push/pull. The answer
     * still stands — a profile the analysis could not read is a question the
     * dry run failed to answer, not a profile it found no work for. */
    if (opts->dry_run) {
        sync_render_dry_run(&results, out);
        err = sync_failure(&results);
        goto cleanup;
    }

    /* Phase 3: Sync with remote (push/pull/divergence handling)
     *
     * Git only — no state is written in this phase, so the write lock is never
     * held across network IO. Nothing catches up afterwards either: the view is
     * computed, and the block that follows only reports what the phase did to it.
     *
     * When all profiles are up-to-date and not in verbose mode, the sync section
     * is ephemeral — shown as progress during execution, cleared after. This
     * avoids noise when there's nothing actionable to report. */
    bool no_push = opts->no_push;
    bool all_quiet = true;
    for (size_t i = 0; i < results.profile_count; i++) {
        const profile_sync_result_t *r = &results.profiles[i];
        if (r->error || r->state != UPSTREAM_UP_TO_DATE) {
            all_quiet = false;
            break;
        }
    }
    bool sync_ephemeral = !output_is_verbose(out) && all_quiet;

    if (sync_ephemeral) {
        output_print(out, OUTPUT_NORMAL, "Syncing with remote...");
        fflush(out->stream);
    }

    err = sync_push_phase(
        repo, remote_name, &results, out, sync_ephemeral, auto_pull, opts->no_pull,
        no_push, diverged_strategy, xfer, config->confirm_destructive
    );

    if (sync_ephemeral) {
        output_clear_line(out);
    }

    if (err) goto cleanup;

    /* What the Git phase left unsaid, said once beneath it: at normal the profiles
     * it had nothing to do for, whose own lines are verbose's (sync_push_phase)
     * — counted after the clear, which would take a line printed before it —
     * and at verbose the wire, Git's tally of what the lines above say moved.
     * Every other profile's line said what the run did with it. */
    size_t up_to_date = 0;
    for (size_t i = 0; i < results.profile_count; i++) {
        const profile_sync_result_t *r = &results.profiles[i];
        if (!r->error && r->state == UPSTREAM_UP_TO_DATE) up_to_date++;
    }
    if (up_to_date > 0 && !output_is_verbose(out)) {
        output_gap(out, OUTPUT_NORMAL);
        output_info(
            out, OUTPUT_NORMAL, "{cyan}%zu{reset} profile%s already up-to-date",
            up_to_date, up_to_date == 1 ? "" : "s"
        );
    }
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
            output_print(out, OUTPUT_NORMAL, "  %s:", s->profile);
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
                "  Their profile has no deployment target here, so nothing lands them."
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
                "'dotta status -v' pairs them."
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
                "lands them."
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

    /* Post-sync fires once the receipt is done — the Git phase's lines, the
     * manifest block and its hint; a failed build was warned above and is not a
     * reason to skip it. Nor is a profile that failed: the pushes and pulls that
     * did land are real, and the hook's subject is the world sync leaves behind,
     * not what sync returns. */
    hook_fire_post(config, out, &hook_inv);

    /* The receipt is printed; the return value is what the caller reads. */
    err = sync_failure(&results);

cleanup:
    /* The one handle the run holds: the transfer, whose close commits the
     * credential decision (sys/transfer.h). state is borrowed from the dispatcher
     * and sync opens no transaction of its own (the flush scopes its own; nothing
     * else writes), and the results are the command arena's. */
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
        "Preview without writing"
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
        "  %s sync -n                 # Preview without writing\n"
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
