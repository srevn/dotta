/**
 * sync.c - Intelligent synchronization command
 */

#include "sync.h"

#include <git2.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base/credentials.h"
#include "base/error.h"
#include "base/gitops.h"
#include "core/profiles.h"
#include "update.h"
#include "utils/array.h"
#include "utils/config.h"
#include "utils/output.h"
#include "utils/repo.h"
#include "utils/upstream.h"

/**
 * Per-profile sync result
 */
typedef struct {
    char *profile_name;
    sync_branch_state_t state;
    size_t ahead;
    size_t behind;
    bool pushed;
    bool failed;
    char *error_message;
} profile_sync_result_t;

/**
 * Overall sync results
 */
typedef struct {
    profile_sync_result_t *profiles;
    size_t count;
    size_t pushed_count;
    size_t need_pull_count;
    size_t diverged_count;
    size_t up_to_date_count;
    size_t no_remote_count;
    size_t failed_count;
    size_t fetch_failed_count;      /* Track fetch failures separately */
    size_t auth_failed_count;        /* Track authentication failures */
} sync_results_t;

/**
 * Create sync results
 */
static sync_results_t *sync_results_create(size_t profile_count) {
    sync_results_t *results = calloc(1, sizeof(sync_results_t));
    if (!results) {
        return NULL;
    }

    results->profiles = calloc(profile_count, sizeof(profile_sync_result_t));
    if (!results->profiles) {
        free(results);
        return NULL;
    }

    results->count = profile_count;
    return results;
}

/**
 * Free sync results
 */
static void sync_results_free(sync_results_t *results) {
    if (!results) {
        return;
    }

    for (size_t i = 0; i < results->count; i++) {
        free(results->profiles[i].profile_name);
        free(results->profiles[i].error_message);
    }

    free(results->profiles);
    free(results);
}

/**
 * Parse divergence strategy from string
 */
static divergence_strategy_t parse_divergence_strategy(const char *str) {
    if (!str) {
        return DIVERGE_WARN;
    }

    if (strcmp(str, "rebase") == 0) {
        return DIVERGE_REBASE;
    } else if (strcmp(str, "merge") == 0) {
        return DIVERGE_MERGE;
    } else if (strcmp(str, "ours") == 0) {
        return DIVERGE_OURS;
    } else if (strcmp(str, "theirs") == 0) {
        return DIVERGE_THEIRS;
    } else if (strcmp(str, "warn") == 0) {
        return DIVERGE_WARN;
    }

    /* Invalid strategy - warn user and fall back to safe default */
    fprintf(stderr, "WARNING: Invalid divergence strategy '%s' (valid: warn, rebase, merge, ours, theirs)\n"
                   "         Falling back to 'warn' (safe default)\n", str);
    return DIVERGE_WARN;  /* Default */
}

/**
 * Parse sync mode from string
 */
static sync_mode_t parse_sync_mode(const char *str, sync_mode_t default_mode) {
    if (!str) {
        return default_mode;
    }

    if (strcmp(str, "local") == 0) {
        return SYNC_MODE_LOCAL;
    } else if (strcmp(str, "auto") == 0) {
        return SYNC_MODE_AUTO;
    } else if (strcmp(str, "all") == 0) {
        return SYNC_MODE_ALL;
    }

    /* Invalid mode - warn user and fall back to default */
    fprintf(stderr, "WARNING: Invalid sync mode '%s' (valid: local, auto, all)\n"
                   "         Falling back to configured default\n", str);
    return default_mode;
}

/**
 * Validate and build a reference name
 *
 * Builds a reference name and validates it fits in the buffer.
 * Git allows up to 255 chars per component, but we use conservative limits.
 *
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param format Printf-style format string
 * @return NULL on success, error message on failure
 */
static const char *build_refname(char *buffer, size_t buffer_size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int written = vsnprintf(buffer, buffer_size, format, args);
    va_end(args);

    if (written < 0) {
        return "Failed to format reference name";
    }

    if ((size_t)written >= buffer_size) {
        return "Reference name too long (truncated)";
    }

    return NULL;  /* Success */
}

/**
 * Prompt user for confirmation (for destructive operations)
 *
 * @param message Confirmation prompt message
 * @param non_interactive_default Default behavior when not running interactively
 * @return true if user confirms, or non_interactive_default if not a TTY
 */
static bool confirm_action(const char *message, bool non_interactive_default) {
    /* Check if stdin is a TTY (interactive terminal) */
    if (!isatty(STDIN_FILENO)) {
        if (non_interactive_default) {
            fprintf(stderr, "WARNING: Running non-interactively, auto-confirming: %s\n", message);
        } else {
            fprintf(stderr, "ERROR: Running non-interactively, refusing destructive operation: %s\n", message);
        }
        return non_interactive_default;
    }

    printf("%s [y/N]: ", message);
    fflush(stdout);

    char response[10];
    if (fgets(response, sizeof(response), stdin) == NULL) {
        return false;
    }

    return (response[0] == 'y' || response[0] == 'Y');
}

/**
 * Helper: Restore HEAD to dotta-worktree with error checking
 */
static void restore_head_to_worktree(git_repository *repo, const char *operation) {
    int git_err = git_repository_set_head(repo, "refs/heads/dotta-worktree");
    if (git_err < 0) {
        fprintf(stderr, "CRITICAL: Failed to restore HEAD to dotta-worktree after %s (error %d)\n",
                operation, git_err);
        fprintf(stderr, "         Your repository HEAD may be in an invalid state.\n");
        fprintf(stderr, "         Run 'git checkout dotta-worktree' manually to fix.\n");
    }
}

/**
 * Helper: Save branch OID for rollback capability
 */
static dotta_error_t *save_branch_oid(
    git_repository *repo,
    const char *branch_name,
    git_oid *out_oid
) {
    char refname[256];
    const char *build_err = build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid branch name '%s': %s", branch_name, build_err);
    }

    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    const git_oid *oid = git_reference_target(ref);
    git_oid_cpy(out_oid, oid);
    git_reference_free(ref);

    return NULL;
}

/**
 * Helper: Rollback branch to saved OID
 */
static dotta_error_t *rollback_branch(
    git_repository *repo,
    const char *branch_name,
    const git_oid *saved_oid
) {
    char refname[256];
    const char *build_err = build_refname(refname, sizeof(refname), "refs/heads/%s", branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid branch name '%s': %s", branch_name, build_err);
    }

    git_reference *ref = NULL;
    int git_err = git_reference_lookup(&ref, repo, refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference *new_ref = NULL;
    git_err = git_reference_set_target(&new_ref, ref, saved_oid, "sync: Rollback after push failure");
    git_reference_free(ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(new_ref);
    return NULL;
}

/**
 * Helper: Verify branch state after merge/rebase
 */
static dotta_error_t *verify_divergence_resolved(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    size_t *out_ahead,
    size_t *out_behind
) {
    upstream_info_t *info = NULL;
    dotta_error_t *err = upstream_analyze_profile(repo, remote_name, branch_name, &info);
    if (err) {
        return err;
    }

    if (out_ahead) *out_ahead = info->ahead;
    if (out_behind) *out_behind = info->behind;

    sync_branch_state_t state = info->state;
    size_t ahead = info->ahead;
    size_t behind = info->behind;
    upstream_info_free(info);

    /* After successful rebase/merge, we should be ahead of remote (or equal) */
    if (state == UPSTREAM_REMOTE_AHEAD) {
        return ERROR(DOTTA_ERR_INTERNAL,
                    "Divergence resolution completed but branch '%s' is still behind remote (%zu commits)",
                    branch_name, behind);
    }

    if (state == UPSTREAM_DIVERGED) {
        return ERROR(DOTTA_ERR_INTERNAL,
                    "Divergence resolution completed but branch '%s' is still diverged (ahead: %zu, behind: %zu)",
                    branch_name, ahead, behind);
    }

    return NULL;
}

/**
 * Resolve divergence with rebase strategy
 *
 * NOTE: This function temporarily modifies the main worktree HEAD to perform
 * the rebase operation (required by libgit2). The HEAD is restored to
 * dotta-worktree on all code paths (success or failure).
 */
static dotta_error_t *resolve_divergence_rebase(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    dotta_error_t *err = NULL;
    char local_refname[256];
    char remote_refname[256];
    const char *build_err;

    build_err = build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid branch name '%s': %s", branch_name, build_err);
    }

    build_err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s", remote_name, branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid remote/branch name '%s/%s': %s", remote_name, branch_name, build_err);
    }

    /* Save original HEAD for emergency restoration */
    git_reference *original_head = NULL;
    int git_err = git_reference_lookup(&original_head, repo, "HEAD");
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Step 1: Checkout the target branch temporarily
     * ARCHITECTURAL NOTE: This violates the "HEAD must always be dotta-worktree" principle.
     * It's done because libgit2's rebase API requires HEAD to point to the branch.
     * We ensure HEAD is restored on ALL code paths below.
     */
    git_err = git_repository_set_head(repo, local_refname);
    if (git_err < 0) {
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 2: Get remote reference */
    git_reference *remote_ref = NULL;
    git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err < 0) {
        restore_head_to_worktree(repo, "rebase (get remote ref)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    const git_oid *remote_oid = git_reference_target(remote_ref);

    /* Step 3: Create annotated commit for rebase */
    git_annotated_commit *remote_head = NULL;
    git_err = git_annotated_commit_lookup(&remote_head, repo, remote_oid);
    git_reference_free(remote_ref);
    if (git_err < 0) {
        restore_head_to_worktree(repo, "rebase (annotated commit)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 4: Perform rebase */
    git_rebase *rebase = NULL;
    git_rebase_options rebase_opts = GIT_REBASE_OPTIONS_INIT;

    const git_annotated_commit *onto = remote_head;
    git_err = git_rebase_init(&rebase, repo, NULL, NULL, onto, &rebase_opts);
    git_annotated_commit_free(remote_head);

    if (git_err < 0) {
        restore_head_to_worktree(repo, "rebase (init)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 5: Iterate through rebase operations */
    git_rebase_operation *op = NULL;
    while ((git_err = git_rebase_next(&op, rebase)) == 0) {
        /* Commit the rebased operation */
        git_oid commit_id;
        git_signature *sig = NULL;

        git_err = git_signature_default(&sig, repo);
        if (git_err < 0) {
            git_rebase_abort(rebase);
            git_rebase_free(rebase);
            restore_head_to_worktree(repo, "rebase (signature)");
            git_reference_free(original_head);
            return error_from_git(git_err);
        }

        git_err = git_rebase_commit(&commit_id, rebase, NULL, sig, NULL, NULL);
        git_signature_free(sig);

        if (git_err < 0) {
            git_rebase_abort(rebase);
            git_rebase_free(rebase);
            restore_head_to_worktree(repo, "rebase (commit)");
            git_reference_free(original_head);
            return error_from_git(git_err);
        }
    }

    /* Step 6: Check if rebase completed successfully */
    if (git_err != GIT_ITEROVER) {
        git_rebase_abort(rebase);
        git_rebase_free(rebase);
        restore_head_to_worktree(repo, "rebase (iteration)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 7: Finish rebase */
    git_err = git_rebase_finish(rebase, NULL);
    git_rebase_free(rebase);

    if (git_err < 0) {
        err = error_from_git(git_err);
    }

    /* Step 8: Restore HEAD to dotta-worktree (CRITICAL - must always happen) */
    restore_head_to_worktree(repo, "rebase (final)");
    git_reference_free(original_head);

    return err;
}

/**
 * Resolve divergence with merge strategy
 *
 * NOTE: This function temporarily modifies the main worktree HEAD to perform
 * the merge operation (required by libgit2). The HEAD is restored to
 * dotta-worktree on all code paths (success or failure).
 */
static dotta_error_t *resolve_divergence_merge(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    dotta_error_t *err = NULL;
    char local_refname[256];
    char remote_refname[256];
    const char *build_err;

    build_err = build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid branch name '%s': %s", branch_name, build_err);
    }

    build_err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s", remote_name, branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid remote/branch name '%s/%s': %s", remote_name, branch_name, build_err);
    }

    /* Save original HEAD for emergency restoration */
    git_reference *original_head = NULL;
    int git_err = git_reference_lookup(&original_head, repo, "HEAD");
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Step 1: Checkout the target branch temporarily
     * ARCHITECTURAL NOTE: This violates the "HEAD must always be dotta-worktree" principle.
     * It's done because libgit2's merge API requires HEAD to point to the branch.
     * We ensure HEAD is restored on ALL code paths below.
     */
    git_err = git_repository_set_head(repo, local_refname);
    if (git_err < 0) {
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 2: Get remote reference */
    git_reference *remote_ref = NULL;
    git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err < 0) {
        restore_head_to_worktree(repo, "merge (get remote ref)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    const git_oid *remote_oid = git_reference_target(remote_ref);

    /* Step 3: Create annotated commit for merge */
    git_annotated_commit *remote_head = NULL;
    git_err = git_annotated_commit_lookup(&remote_head, repo, remote_oid);
    git_reference_free(remote_ref);
    if (git_err < 0) {
        restore_head_to_worktree(repo, "merge (annotated commit)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 4: Perform merge */
    git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE;  /* Force since no working tree conflicts */

    const git_annotated_commit *merge_heads[] = { remote_head };
    git_err = git_merge(repo, merge_heads, 1, &merge_opts, &checkout_opts);
    git_annotated_commit_free(remote_head);

    if (git_err < 0) {
        restore_head_to_worktree(repo, "merge (perform)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Step 5: Check for conflicts */
    git_index *index = NULL;
    git_err = git_repository_index(&index, repo);
    if (git_err < 0) {
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (get index)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    if (git_index_has_conflicts(index)) {
        git_index_free(index);
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (conflicts)");
        git_reference_free(original_head);
        return ERROR(DOTTA_ERR_CONFLICT,
                    "Merge resulted in conflicts for '%s'. Please resolve manually.",
                    branch_name);
    }

    /* Step 6: Write the merge commit */
    git_oid tree_oid, commit_oid;
    git_err = git_index_write_tree(&tree_oid, index);
    git_index_free(index);
    if (git_err < 0) {
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (write tree)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    git_tree *tree = NULL;
    git_err = git_tree_lookup(&tree, repo, &tree_oid);
    if (git_err < 0) {
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (lookup tree)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Get local branch commit (now HEAD since we checked it out) */
    git_reference *local_ref = NULL;
    git_commit *local_commit = NULL;
    git_err = git_reference_lookup(&local_ref, repo, local_refname);
    if (git_err < 0) {
        git_tree_free(tree);
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (lookup local ref)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    const git_oid *local_oid = git_reference_target(local_ref);
    git_err = git_commit_lookup(&local_commit, repo, local_oid);
    git_reference_free(local_ref);
    if (git_err < 0) {
        git_tree_free(tree);
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (lookup local commit)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Get remote commit */
    git_commit *remote_commit = NULL;
    git_err = git_commit_lookup(&remote_commit, repo, remote_oid);
    if (git_err < 0) {
        git_commit_free(local_commit);
        git_tree_free(tree);
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (lookup remote commit)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    /* Create merge commit */
    git_signature *sig = NULL;
    git_err = git_signature_default(&sig, repo);
    if (git_err < 0) {
        git_commit_free(remote_commit);
        git_commit_free(local_commit);
        git_tree_free(tree);
        git_repository_state_cleanup(repo);
        restore_head_to_worktree(repo, "merge (signature)");
        git_reference_free(original_head);
        return error_from_git(git_err);
    }

    char message[256];
    snprintf(message, sizeof(message), "Merge remote-tracking branch '%s/%s'", remote_name, branch_name);

    const git_commit *parents[] = { local_commit, remote_commit };
    git_err = git_commit_create(&commit_oid, repo, local_refname, sig, sig, NULL, message, tree, 2, parents);

    git_signature_free(sig);
    git_commit_free(remote_commit);
    git_commit_free(local_commit);
    git_tree_free(tree);

    if (git_err < 0) {
        err = error_from_git(git_err);
    }

    /* Step 7: Cleanup and restore HEAD to dotta-worktree (CRITICAL - must always happen) */
    git_repository_state_cleanup(repo);
    restore_head_to_worktree(repo, "merge (final)");
    git_reference_free(original_head);

    return err;
}

/**
 * Resolve divergence with "ours" strategy (force push local)
 */
static dotta_error_t *resolve_divergence_ours(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    credential_context_t *cred_ctx,
    bool confirm
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    if (confirm) {
        char prompt[512];
        snprintf(prompt, sizeof(prompt),
                "WARNING: This will force push and OVERWRITE remote '%s' with local changes.\n"
                "Remote commits will be LOST. Continue?",
                branch_name);

        if (!confirm_action(prompt, false)) {  /* Never auto-confirm force push */
            printf("Operation cancelled.\n");
            return NULL;  /* User declined, not an error */
        }
    }

    /* Force push local to remote */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    push_opts.callbacks.credentials = credentials_callback;
    push_opts.callbacks.payload = cred_ctx;

    /* Force push refspec */
    char refspec[256];
    snprintf(refspec, sizeof(refspec), "+refs/heads/%s:refs/heads/%s", branch_name, branch_name);

    const char *refspecs[] = { refspec };
    git_strarray refs = { (char **)refspecs, 1 };

    git_err = git_remote_push(remote, &refs, &push_opts);
    git_remote_free(remote);

    if (git_err < 0) {
        if (cred_ctx) {
            credential_context_reject(cred_ctx);
        }
        return error_from_git(git_err);
    }

    if (cred_ctx) {
        credential_context_approve(cred_ctx);
    }

    return NULL;
}

/**
 * Resolve divergence with "theirs" strategy (reset to remote)
 */
static dotta_error_t *resolve_divergence_theirs(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name,
    bool confirm
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    if (confirm) {
        char prompt[512];
        snprintf(prompt, sizeof(prompt),
                "WARNING: This will reset '%s' to remote and DISCARD local commits.\n"
                "Local changes will be LOST. Continue?",
                branch_name);

        if (!confirm_action(prompt, false)) {  /* Never auto-confirm reset */
            printf("Operation cancelled.\n");
            return NULL;  /* User declined, not an error */
        }
    }

    /* Get remote reference */
    char remote_refname[256];
    const char *build_err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s", remote_name, branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid remote/branch name '%s/%s': %s", remote_name, branch_name, build_err);
    }

    git_reference *remote_ref = NULL;
    int git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    const git_oid *remote_oid = git_reference_target(remote_ref);

    /* Reset local branch to remote */
    char local_refname[256];
    build_err = build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);
    if (build_err) {
        git_reference_free(remote_ref);
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid branch name '%s': %s", branch_name, build_err);
    }

    git_reference *local_ref = NULL;
    git_err = git_reference_lookup(&local_ref, repo, local_refname);
    if (git_err < 0) {
        git_reference_free(remote_ref);
        return error_from_git(git_err);
    }

    git_reference *new_ref = NULL;
    git_err = git_reference_set_target(&new_ref, local_ref, remote_oid,
                                      "sync: Reset to remote (theirs strategy)");
    git_reference_free(local_ref);
    git_reference_free(remote_ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(new_ref);
    return NULL;
}

/**
 * Pull branch with fast-forward only
 * Returns true if branch was updated
 */
static dotta_error_t *pull_branch_ff(
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
    char local_refname[256];
    char remote_refname[256];
    const char *build_err;

    build_err = build_refname(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid branch name '%s': %s", branch_name, build_err);
    }

    build_err = build_refname(remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s", remote_name, branch_name);
    if (build_err) {
        return ERROR(DOTTA_ERR_INVALID_ARG, "Invalid remote/branch name '%s/%s': %s", remote_name, branch_name, build_err);
    }

    git_reference *local_ref = NULL;
    git_reference *remote_ref = NULL;

    int git_err = git_reference_lookup(&local_ref, repo, local_refname);
    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err < 0) {
        git_reference_free(local_ref);
        if (git_err == GIT_ENOTFOUND) {
            /* Remote branch doesn't exist */
            return NULL;
        }
        return error_from_git(git_err);
    }

    const git_oid *remote_oid = git_reference_target(remote_ref);
    const git_oid *local_oid = git_reference_target(local_ref);

    /* Check if branches are at the same commit (up-to-date) */
    if (git_oid_equal(local_oid, remote_oid)) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        /* Already up-to-date, nothing to do */
        return NULL;
    }

    /* Check if fast-forward is possible by checking if local is ancestor of remote
     * This is independent of where HEAD is currently pointing, which is important
     * because we're always on dotta-worktree, not on the branch we're updating.
     */
    git_err = git_graph_descendant_of(repo, remote_oid, local_oid);
    if (git_err < 0) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        return error_from_git(git_err);
    }

    if (git_err == 0) {
        /* local is NOT an ancestor of remote - cannot fast-forward */
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        return ERROR(DOTTA_ERR_CONFLICT,
                    "Cannot fast-forward '%s' - branches have diverged", branch_name);
    }

    /* git_err == 1 means local IS an ancestor of remote - can fast-forward */

    /* Perform fast-forward */
    git_reference *updated_ref = NULL;
    git_err = git_reference_set_target(&updated_ref, local_ref, remote_oid,
                                      "sync: Fast-forward pull");
    git_reference_free(local_ref);
    git_reference_free(remote_ref);

    if (git_err < 0) {
        return error_from_git(git_err);
    }

    git_reference_free(updated_ref);
    *updated = true;
    return NULL;
}

/**
 * Phase 1: Update local profiles with modified files
 */
static dotta_error_t *sync_update_phase(
    git_repository *repo,
    const cmd_sync_options_t *opts,
    output_ctx_t *out,
    bool *had_updates
) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);
    CHECK_NULL(out);
    CHECK_NULL(had_updates);

    *had_updates = false;

    output_section(out, "Updating local profiles");

    /* Build update options */
    cmd_update_options_t update_opts = {
        .files = NULL,
        .file_count = 0,
        .profiles = opts->profiles,
        .profile_count = opts->profile_count,
        .message = opts->message,
        .dry_run = opts->dry_run,
        .interactive = false,
        .verbose = opts->verbose,
        .include_new = opts->include_new,
        .only_new = opts->only_new
    };

    /* Run update */
    dotta_error_t *err = cmd_update(repo, &update_opts);
    if (err) {
        /* Check if it's just "no modified files" */
        if (strstr(error_message(err), "No modified files")) {
            error_free(err);
            output_info(out, "No local changes to update");
            return NULL;
        }
        return err;
    }

    *had_updates = true;
    fprintf(out->stream, "\n");
    return NULL;
}


/**
 * Helper: Collect existing remote tracking branches
 */
static dotta_error_t *collect_remote_tracking_branches(
    git_repository *repo,
    const char *remote_name,
    string_array_t **out_branches
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(out_branches);

    string_array_t *branches = string_array_create();
    if (!branches) {
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create array");
    }

    /* Iterate through all references looking for remote tracking branches */
    git_reference_iterator *iter = NULL;
    int git_err = git_reference_iterator_new(&iter, repo);
    if (git_err < 0) {
        string_array_free(branches);
        return error_from_git(git_err);
    }

    char prefix[256];
    snprintf(prefix, sizeof(prefix), "refs/remotes/%s/", remote_name);
    size_t prefix_len = strlen(prefix);

    git_reference *ref = NULL;
    while (git_reference_next(&ref, iter) == 0) {
        const char *refname = git_reference_name(ref);
        if (strncmp(refname, prefix, prefix_len) == 0) {
            /* Extract branch name */
            const char *branch_name = refname + prefix_len;
            string_array_push(branches, branch_name);
        }
        git_reference_free(ref);
    }

    git_reference_iterator_free(iter);

    *out_branches = branches;
    return NULL;
}

/**
 * Helper: Delete local branches whose remote tracking branches were pruned
 *
 * Compares the list of remote tracking branches before and after fetch.
 * If a branch existed before but not after (was pruned), delete the local branch.
 */
static dotta_error_t *delete_orphaned_local_branches(
    git_repository *repo,
    const char *remote_name,
    string_array_t *before_branches,
    profile_list_t *profiles,
    output_ctx_t *out,
    bool verbose
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(before_branches);
    CHECK_NULL(profiles);
    CHECK_NULL(out);

    /* Get current remote tracking branches */
    string_array_t *after_branches = NULL;
    dotta_error_t *err = collect_remote_tracking_branches(repo, remote_name, &after_branches);
    if (err) {
        return err;
    }

    /* Find branches that were pruned (existed before but not after) */
    string_array_t *to_delete = string_array_create();
    if (!to_delete) {
        string_array_free(after_branches);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create array");
    }

    for (size_t i = 0; i < string_array_size(before_branches); i++) {
        const char *branch_name = string_array_get(before_branches, i);

        /* Skip dotta-worktree */
        if (strcmp(branch_name, "dotta-worktree") == 0) {
            continue;
        }

        /* Check if this branch still exists in after_branches */
        bool found = false;
        for (size_t j = 0; j < string_array_size(after_branches); j++) {
            if (strcmp(branch_name, string_array_get(after_branches, j)) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            /* Branch was pruned - mark local branch for deletion */
            string_array_push(to_delete, branch_name);
        }
    }

    string_array_free(after_branches);

    /* Delete orphaned branches */
    size_t deleted_count = 0;
    for (size_t i = 0; i < string_array_size(to_delete); i++) {
        const char *branch_name = string_array_get(to_delete, i);

        if (verbose) {
            output_info(out, "  Deleting local branch '%s' (removed from remote)...", branch_name);
        }

        /* Delete the local branch */
        char local_refname[256];
        snprintf(local_refname, sizeof(local_refname), "refs/heads/%s", branch_name);

        git_reference *local_ref = NULL;
        int git_err = git_reference_lookup(&local_ref, repo, local_refname);
        if (git_err == 0) {
            git_err = git_reference_delete(local_ref);
            git_reference_free(local_ref);

            if (git_err == 0) {
                deleted_count++;
                if (verbose) {
                    output_success(out, "    Deleted local branch '%s'", branch_name);
                }
            } else {
                output_warning(out, "    Failed to delete local branch '%s': %s",
                              branch_name, git_error_last()->message);
            }
        }
    }

    string_array_free(to_delete);

    if (deleted_count > 0 && verbose) {
        output_info(out, "Deleted %zu orphaned local branch%s",
                   deleted_count, deleted_count == 1 ? "" : "es");
    }

    return NULL;
}

/**
 * Phase 2: Fetch from remote
 *
 * Supports three sync modes:
 * - SYNC_MODE_LOCAL: Fetch all local branches + discover new remote branches
 * - SYNC_MODE_AUTO: Fetch only auto-detected profiles
 * - SYNC_MODE_ALL: Fetch all remote branches
 */
static dotta_error_t *sync_fetch_phase(
    git_repository *repo,
    const char *remote_name,
    sync_mode_t sync_mode,
    profile_list_t **profiles,
    sync_results_t **results,
    output_ctx_t *out,
    bool verbose,
    credential_context_t *cred_ctx
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(profiles);
    CHECK_NULL(*profiles);
    CHECK_NULL(results);
    CHECK_NULL(out);

    /* Check if remote exists */
    git_remote *remote = NULL;
    int git_err = git_remote_lookup(&remote, repo, remote_name);
    if (git_err == GIT_ENOTFOUND) {
        return ERROR(DOTTA_ERR_NOT_FOUND,
                    "No remote '%s' configured\n"
                    "Hint: Run 'dotta remote add %s <url>' to add a remote",
                    remote_name, remote_name);
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }
    git_remote_free(remote);

    char section_title[256];
    snprintf(section_title, sizeof(section_title), "Fetching from remote '%s'", remote_name);
    output_section(out, section_title);

    bool auth_failed = false;
    size_t fetch_success_count = 0;
    profile_list_t *final_profiles = *profiles;
    dotta_error_t *err = NULL;

    /* Fetch based on sync mode */
    if (sync_mode == SYNC_MODE_ALL) {
        /* First, fetch all remote refs to populate remote tracking branches */
        if (verbose) {
            output_info(out, "Fetching all remote refs...");
        }

        git_remote *fetch_remote = NULL;
        int git_err = git_remote_lookup(&fetch_remote, repo, remote_name);
        if (git_err < 0) {
            return error_from_git(git_err);
        }

        /* Fetch with default refspec (fetches all branches)
         * Enable pruning to remove stale remote tracking branches
         */
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        fetch_opts.callbacks.credentials = credentials_callback;
        fetch_opts.callbacks.payload = cred_ctx;
        fetch_opts.prune = GIT_FETCH_PRUNE;  /* Prune stale remote branches */

        git_err = git_remote_fetch(fetch_remote, NULL, &fetch_opts, NULL);
        git_remote_free(fetch_remote);

        if (git_err < 0) {
            return error_from_git(git_err);
        }

        /* Now discover which remote branches don't have local branches */
        string_array_t *remote_branches = NULL;
        dotta_error_t *err = upstream_discover_branches(repo, remote_name, &remote_branches);
        if (err) {
            return error_wrap(err, "Failed to discover remote branches");
        }

        /* Create local tracking branches for discovered branches */
        for (size_t i = 0; i < string_array_size(remote_branches); i++) {
            const char *branch_name = string_array_get(remote_branches, i);

            if (verbose) {
                output_info(out, "  Creating local branch '%s' from remote...", branch_name);
            }

            err = upstream_create_tracking_branch(repo, remote_name, branch_name);
            if (err) {
                output_warning(out, "Failed to create local branch '%s': %s",
                              branch_name, error_message(err));
                error_free(err);
            }
        }

        string_array_free(remote_branches);

        /* Reload all local profiles */
        profile_list_free(final_profiles);
        err = profile_list_all_local(repo, &final_profiles);
        if (err) {
            return error_wrap(err, "Failed to reload local profiles");
        }

        *profiles = final_profiles;

        /* Recreate results tracker with new profile count */
        if (*results) {
            sync_results_free(*results);
        }
        *results = sync_results_create(final_profiles->count);
        if (!*results) {
            return ERROR(DOTTA_ERR_MEMORY, "Failed to create results");
        }
    } else if (sync_mode == SYNC_MODE_LOCAL) {
        /* Collect remote tracking branches BEFORE fetch to detect deletions */
        string_array_t *before_remote_branches = NULL;
        err = collect_remote_tracking_branches(repo, remote_name, &before_remote_branches);
        if (err) {
            return error_wrap(err, "Failed to collect remote tracking branches");
        }

        /* Fetch all remote refs to populate remote tracking branches
         * This is necessary so upstream_discover_branches can see what's on the remote
         */
        git_remote *fetch_remote = NULL;
        int git_err = git_remote_lookup(&fetch_remote, repo, remote_name);
        if (git_err < 0) {
            string_array_free(before_remote_branches);
            return error_from_git(git_err);
        }

        /* Fetch with default refspec (fetches all branches)
         * Enable pruning to remove stale remote tracking branches
         */
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        fetch_opts.callbacks.credentials = credentials_callback;
        fetch_opts.callbacks.payload = cred_ctx;
        fetch_opts.prune = GIT_FETCH_PRUNE;  /* Prune stale remote branches */

        git_err = git_remote_fetch(fetch_remote, NULL, &fetch_opts, NULL);
        git_remote_free(fetch_remote);

        if (git_err < 0) {
            string_array_free(before_remote_branches);
            return error_from_git(git_err);
        }

        /* Delete orphaned local branches (branches whose remote was deleted) */
        err = delete_orphaned_local_branches(repo, remote_name, before_remote_branches, *profiles, out, verbose);
        string_array_free(before_remote_branches);
        if (err) {
            return error_wrap(err, "Failed to delete orphaned local branches");
        }

        /* Reload profiles after deletion to get updated list */
        profile_list_free(final_profiles);
        err = profile_list_all_local(repo, &final_profiles);
        if (err) {
            return error_wrap(err, "Failed to reload local profiles after deletion");
        }
        *profiles = final_profiles;

        /* Recreate results tracker with updated profile count */
        if (*results) {
            sync_results_free(*results);
        }
        *results = sync_results_create(final_profiles->count);
        if (!*results) {
            return ERROR(DOTTA_ERR_MEMORY, "Failed to create results");
        }

        /* Now discover new remote branches not in local list */
        string_array_t *new_branches = NULL;
        err = upstream_discover_branches(repo, remote_name, &new_branches);
        if (err) {
            return error_wrap(err, "Failed to discover remote branches");
        }

        size_t discovered_count = string_array_size(new_branches);
        if (discovered_count > 0) {
            if (verbose) {
                output_info(out, "Discovered %zu new remote branch%s",
                           discovered_count, discovered_count == 1 ? "" : "es");
            }

            /* Create local tracking branches */
            for (size_t i = 0; i < discovered_count; i++) {
                const char *branch_name = string_array_get(new_branches, i);

                if (verbose) {
                    output_info(out, "  Creating local branch '%s'...", branch_name);
                }

                err = upstream_create_tracking_branch(repo, remote_name, branch_name);
                if (err) {
                    output_warning(out, "Failed to create local branch '%s': %s",
                                  branch_name, error_message(err));
                    error_free(err);
                }
            }

            /* Reload all local profiles */
            profile_list_free(final_profiles);
            err = profile_list_all_local(repo, &final_profiles);
            if (err) {
                string_array_free(new_branches);
                return error_wrap(err, "Failed to reload local profiles");
            }

            *profiles = final_profiles;

            /* Recreate results tracker */
            if (*results) {
                sync_results_free(*results);
            }
            *results = sync_results_create(final_profiles->count);
            if (!*results) {
                string_array_free(new_branches);
                return ERROR(DOTTA_ERR_MEMORY, "Failed to create results");
            }
        }

        string_array_free(new_branches);
    }
    /* SYNC_MODE_AUTO: Use profiles as-is (existing behavior) */

    /* Fetch each profile branch */
    for (size_t i = 0; i < final_profiles->count; i++) {
        const char *branch_name = final_profiles->profiles[i].name;

        /* Skip remaining fetches if authentication failed */
        if (auth_failed) {
            output_info(out, "  Skipping %s (authentication failed)", branch_name);
            (*results)->fetch_failed_count++;
            continue;
        }

        if (verbose) {
            output_info(out, "  Fetching %s...", branch_name);
        }

        dotta_error_t *err = gitops_fetch_branch(repo, remote_name, branch_name, cred_ctx);
        if (err) {
            /* Check if this is an authentication error */
            const char *err_msg = error_message(err);
            if (strstr(err_msg, "authentication") || strstr(err_msg, "credentials") ||
                strstr(err_msg, "permission denied") || strstr(err_msg, "unauthorized")) {
                auth_failed = true;
                (*results)->auth_failed_count++;
                output_error(out, "Authentication failed for '%s': %s", branch_name, err_msg);
                output_error(out, "Skipping remaining fetches due to authentication failure");
            } else {
                output_warning(out, "Failed to fetch '%s': %s", branch_name, err_msg);
            }
            (*results)->fetch_failed_count++;
            error_free(err);
        } else {
            fetch_success_count++;
        }
    }

    /* Error if all fetches failed */
    if (fetch_success_count == 0 && final_profiles->count > 0) {
        return ERROR(DOTTA_ERR_GIT,
                    "All fetch operations failed\n"
                    "Hint: Check network connectivity and remote accessibility");
    }

    fprintf(out->stream, "\n");
    return NULL;
}

/**
 * Phase 3: Analyze branch states
 */
static dotta_error_t *sync_analyze_phase(
    git_repository *repo,
    const char *remote_name,
    profile_list_t *profiles,
    sync_results_t *results,
    output_ctx_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(profiles);
    CHECK_NULL(results);
    CHECK_NULL(out);

    for (size_t i = 0; i < profiles->count; i++) {
        profile_t *profile = &profiles->profiles[i];
        profile_sync_result_t *result = &results->profiles[i];

        result->profile_name = strdup(profile->name);
        if (!result->profile_name) {
            return ERROR(DOTTA_ERR_MEMORY, "Failed to allocate profile name");
        }

        /* Analyze state */
        upstream_info_t *info = NULL;
        dotta_error_t *err = upstream_analyze_profile(repo, remote_name, profile->name, &info);

        if (err) {
            result->failed = true;
            result->error_message = strdup(error_message(err));
            results->failed_count++;
            error_free(err);
            continue;
        }

        result->state = info->state;
        result->ahead = info->ahead;
        result->behind = info->behind;
        upstream_info_free(info);

        /* Update counters */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE:
                results->up_to_date_count++;
                break;
            case UPSTREAM_LOCAL_AHEAD:
                /* Can push */
                break;
            case UPSTREAM_REMOTE_AHEAD:
                results->need_pull_count++;
                break;
            case UPSTREAM_DIVERGED:
                results->diverged_count++;
                break;
            case UPSTREAM_NO_REMOTE:
                results->no_remote_count++;
                break;
            case UPSTREAM_UNKNOWN:
                /* Skip unknown states */
                break;
        }
    }

    return NULL;
}

/**
 * Phase 4: Sync branches with remote (push/pull/divergence handling)
 */
static dotta_error_t *sync_push_phase(
    git_repository *repo,
    const char *remote_name,
    sync_results_t *results,
    output_ctx_t *out,
    bool verbose,
    bool auto_pull,
    divergence_strategy_t diverged_strategy,
    credential_context_t *cred_ctx,
    bool confirm_destructive
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(results);
    CHECK_NULL(out);

    output_section(out, "Syncing with remote");

    for (size_t i = 0; i < results->count; i++) {
        profile_sync_result_t *result = &results->profiles[i];

        /* Skip failed analysis */
        if (result->failed) {
            output_error(out, "  %s: %s", result->profile_name, result->error_message);
            continue;
        }

        /* Handle based on state */
        switch (result->state) {
            case UPSTREAM_UP_TO_DATE:
                if (verbose) {
                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    printf("  = %s: up-to-date\n", colored ? colored : result->profile_name);
                    free(colored);
                }
                break;

            case UPSTREAM_LOCAL_AHEAD: {
                /* Safe to push - local has new commits */
                if (verbose) {
                    printf("  Pushing %s (%zu commit%s)...\n",
                           result->profile_name,
                           result->ahead, result->ahead == 1 ? "" : "s");
                }

                dotta_error_t *err = gitops_push_branch(repo, remote_name, result->profile_name, cred_ctx);
                if (err) {
                    result->failed = true;
                    result->error_message = strdup(error_message(err));
                    results->failed_count++;
                    output_error(out, "  ✗ %s: push failed - %s",
                                result->profile_name, error_message(err));
                    error_free(err);
                } else {
                    result->pushed = true;
                    results->pushed_count++;

                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    printf("  ✓ %s: pushed %zu commit%s\n",
                           colored ? colored : result->profile_name,
                           result->ahead, result->ahead == 1 ? "" : "s");
                    free(colored);
                }
                break;
            }

            case UPSTREAM_NO_REMOTE: {
                /* Remote branch doesn't exist - create it */
                if (verbose) {
                    printf("  Creating remote branch %s...\n", result->profile_name);
                }

                dotta_error_t *err = gitops_push_branch(repo, remote_name, result->profile_name, cred_ctx);
                if (err) {
                    result->failed = true;
                    result->error_message = strdup(error_message(err));
                    results->failed_count++;
                    output_error(out, "  ✗ %s: failed to create remote branch - %s",
                                result->profile_name, error_message(err));
                    error_free(err);
                } else {
                    result->pushed = true;
                    results->pushed_count++;

                    char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                    printf("  ✓ %s: created remote branch\n",
                           colored ? colored : result->profile_name);
                    free(colored);
                }
                break;
            }

            case UPSTREAM_REMOTE_AHEAD: {
                if (auto_pull) {
                    /* Auto-pull when safe (fast-forward only) */
                    if (verbose) {
                        printf("  Pulling %s (%zu commit%s behind)...\n",
                               result->profile_name,
                               result->behind, result->behind == 1 ? "" : "s");
                    }

                    bool pulled = false;
                    dotta_error_t *err = pull_branch_ff(repo, remote_name, result->profile_name, &pulled);
                    if (err) {
                        result->failed = true;
                        result->error_message = strdup(error_message(err));
                        results->failed_count++;
                        output_error(out, "  ✗ %s: pull failed - %s",
                                    result->profile_name, error_message(err));
                        error_free(err);
                    } else if (pulled) {
                        char *colored = output_colorize(out, OUTPUT_COLOR_GREEN, result->profile_name);
                        printf("  ✓ %s: pulled %zu commit%s (fast-forward)\n",
                               colored ? colored : result->profile_name,
                               result->behind, result->behind == 1 ? "" : "s");
                        free(colored);
                    }
                } else {
                    /* Just warn - don't auto-pull */
                    char *colored = output_colorize(out, OUTPUT_COLOR_YELLOW, result->profile_name);
                    printf("  ↓ %s: remote has %zu new commit%s\n",
                           colored ? colored : result->profile_name,
                           result->behind, result->behind == 1 ? "" : "s");
                    printf("     Hint: Run 'dotta pull' or enable auto_pull in config to automatically pull\n");
                    free(colored);
                }
                break;
            }

            case UPSTREAM_DIVERGED: {
                /* Handle divergence based on strategy */
                char *colored = output_colorize(out, OUTPUT_COLOR_RED, result->profile_name);
                printf("  ⚠ %s: diverged (%zu local, %zu remote commits)\n",
                       colored ? colored : result->profile_name,
                       result->ahead, result->behind);
                free(colored);

                dotta_error_t *err = NULL;
                switch (diverged_strategy) {
                    case DIVERGE_WARN:
                        printf("     Hint: Use --diverged=<strategy> or set sync.diverged_strategy in config\n");
                        printf("     Strategies: rebase, merge, ours (keep local), theirs (keep remote)\n");
                        results->diverged_count++;
                        break;

                    case DIVERGE_REBASE: {
                        printf("     Resolving with rebase strategy...\n");

                        /* Save original branch state for rollback */
                        git_oid saved_oid;
                        err = save_branch_oid(repo, result->profile_name, &saved_oid);
                        if (err) {
                            output_error(out, "     ✗ Failed to save branch state: %s", error_message(err));
                            error_free(err);
                            break;
                        }

                        err = resolve_divergence_rebase(repo, remote_name, result->profile_name);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "     ✗ Rebase failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            /* Verify rebase succeeded */
                            size_t ahead = 0;
                            err = verify_divergence_resolved(repo, remote_name, result->profile_name, &ahead, NULL);
                            if (err) {
                                output_error(out, "     ✗ Rebase verification failed: %s", error_message(err));
                                error_free(err);
                                /* Rollback */
                                err = rollback_branch(repo, result->profile_name, &saved_oid);
                                if (err) {
                                    output_error(out, "     ✗ Rollback failed: %s", error_message(err));
                                    error_free(err);
                                } else {
                                    printf("     ↺ Rolled back to original state\n");
                                }
                            } else {
                                printf("     ✓ Successfully rebased onto remote (%zu commit%s to push)\n",
                                       ahead, ahead == 1 ? "" : "s");

                                /* Now push the rebased commits */
                                err = gitops_push_branch(repo, remote_name, result->profile_name, cred_ctx);
                                if (err) {
                                    output_error(out, "     ✗ Push after rebase failed: %s", error_message(err));
                                    error_free(err);
                                    /* Rollback since push failed */
                                    printf("     ↺ Rolling back rebase (push failed)...\n");
                                    err = rollback_branch(repo, result->profile_name, &saved_oid);
                                    if (err) {
                                        output_error(out, "     ✗ Rollback failed: %s", error_message(err));
                                        error_free(err);
                                    } else {
                                        printf("     ✓ Rolled back to original state\n");
                                    }
                                } else {
                                    printf("     ✓ Pushed rebased commits\n");
                                    result->pushed = true;
                                    results->pushed_count++;
                                }
                            }
                        }
                        break;
                    }

                    case DIVERGE_MERGE: {
                        printf("     Resolving with merge strategy...\n");

                        /* Save original branch state for rollback */
                        git_oid saved_oid;
                        err = save_branch_oid(repo, result->profile_name, &saved_oid);
                        if (err) {
                            output_error(out, "     ✗ Failed to save branch state: %s", error_message(err));
                            error_free(err);
                            break;
                        }

                        err = resolve_divergence_merge(repo, remote_name, result->profile_name);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "     ✗ Merge failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            /* Verify merge succeeded */
                            size_t ahead = 0;
                            err = verify_divergence_resolved(repo, remote_name, result->profile_name, &ahead, NULL);
                            if (err) {
                                output_error(out, "     ✗ Merge verification failed: %s", error_message(err));
                                error_free(err);
                                /* Rollback */
                                err = rollback_branch(repo, result->profile_name, &saved_oid);
                                if (err) {
                                    output_error(out, "     ✗ Rollback failed: %s", error_message(err));
                                    error_free(err);
                                } else {
                                    printf("     ↺ Rolled back to original state\n");
                                }
                            } else {
                                printf("     ✓ Successfully merged with remote (%zu commit%s to push)\n",
                                       ahead, ahead == 1 ? "" : "s");

                                /* Now push the merge commit */
                                err = gitops_push_branch(repo, remote_name, result->profile_name, cred_ctx);
                                if (err) {
                                    output_error(out, "     ✗ Push after merge failed: %s", error_message(err));
                                    error_free(err);
                                    /* Rollback since push failed */
                                    printf("     ↺ Rolling back merge (push failed)...\n");
                                    err = rollback_branch(repo, result->profile_name, &saved_oid);
                                    if (err) {
                                        output_error(out, "     ✗ Rollback failed: %s", error_message(err));
                                        error_free(err);
                                    } else {
                                        printf("     ✓ Rolled back to original state\n");
                                    }
                                } else {
                                    printf("     ✓ Pushed merge commit\n");
                                    result->pushed = true;
                                    results->pushed_count++;
                                }
                            }
                        }
                        break;
                    }

                    case DIVERGE_OURS:
                        printf("     Resolving with 'ours' strategy (force push)...\n");
                        err = resolve_divergence_ours(repo, remote_name, result->profile_name,
                                                      cred_ctx, confirm_destructive);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "     ✗ Force push failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            printf("     ✓ Forced push to remote (remote commits discarded)\n");
                        }
                        break;

                    case DIVERGE_THEIRS:
                        printf("     Resolving with 'theirs' strategy (reset to remote)...\n");
                        err = resolve_divergence_theirs(repo, remote_name, result->profile_name,
                                                        confirm_destructive);
                        if (err) {
                            result->failed = true;
                            result->error_message = strdup(error_message(err));
                            results->failed_count++;
                            output_error(out, "     ✗ Reset failed: %s", error_message(err));
                            error_free(err);
                        } else {
                            printf("     ✓ Reset to remote (local commits discarded)\n");
                        }
                        break;
                }
                break;
            }

            case UPSTREAM_UNKNOWN:
                /* Skip profiles with unknown state */
                output_warning(out, "  ? %s: state unknown", result->profile_name);
                break;
        }
    }

    fprintf(out->stream, "\n");
    return NULL;
}

/**
 * Sync command implementation
 */
dotta_error_t *cmd_sync(git_repository *repo, const cmd_sync_options_t *opts) {
    CHECK_NULL(repo);
    CHECK_NULL(opts);

    dotta_error_t *err = NULL;
    dotta_config_t *config = NULL;
    profile_list_t *profiles = NULL;
    sync_results_t *results = NULL;
    char *remote_name = NULL;

    /* Verify main worktree is on dotta-worktree branch */
    char *current_branch = NULL;
    err = gitops_current_branch(repo, &current_branch);
    if (err) {
        return error_wrap(err, "Failed to get current branch");
    }

    if (strcmp(current_branch, "dotta-worktree") != 0) {
        free(current_branch);
        return ERROR(DOTTA_ERR_STATE_INVALID,
                    "Main worktree must be on 'dotta-worktree' branch (currently on '%s')\n"
                    "Hint: Run 'git checkout dotta-worktree' to fix",
                    current_branch);
    }
    free(current_branch);

    /* Load configuration */
    err = config_load(NULL, &config);
    if (err) {
        /* Non-fatal: continue with defaults */
        config = config_create_default();
    }

    /* Create output context from config */
    output_ctx_t *out = output_create_from_config(config);
    if (!out) {
        config_free(config);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create output context");
    }

    /* CLI flags override config */
    if (opts->verbose) {
        output_set_verbosity(out, OUTPUT_VERBOSE);
    }

    /* Determine sync mode: CLI overrides config */
    sync_mode_t sync_mode = parse_sync_mode(opts->mode, config->sync_mode);

    /* Load profiles based on sync mode */
    if (sync_mode == SYNC_MODE_LOCAL || sync_mode == SYNC_MODE_ALL) {
        /* For LOCAL and ALL modes: load all local branches initially
         * (remote discovery happens during fetch phase) */
        err = profile_list_all_local(repo, &profiles);
        if (err) {
            config_free(config);
            output_free(out);
            return error_wrap(err, "Failed to load local profiles");
        }
    } else {
        /* For AUTO mode: use standard profile resolution */
        err = profile_load_with_fallback(repo, opts->profiles, opts->profile_count,
                                          (const char **)config->profile_order,
                                          config->profile_order_count,
                                          config->auto_detect, config->strict_mode, &profiles);
        if (err) {
            config_free(config);
            output_free(out);
            return error_wrap(err, "Failed to load profiles");
        }
    }

    if (profiles->count == 0) {
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_NOT_FOUND, "No profiles found");
    }

    /* Create results tracker */
    results = sync_results_create(profiles->count);
    if (!results) {
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return ERROR(DOTTA_ERR_MEMORY, "Failed to create results");
    }

    /* Phase 1: Update local profiles */
    bool had_updates = false;
    err = sync_update_phase(repo, opts, out, &had_updates);
    if (err) {
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Exit early if dry run */
    if (opts->dry_run) {
        output_info(out, "Dry run: no changes made");
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return NULL;
    }

    /* Exit if no-push flag set */
    if (opts->no_push) {
        output_info(out, "Update complete (--no-push specified)");
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return NULL;
    }

    /* Auto-detect remote */
    err = upstream_detect_remote(repo, &remote_name);
    if (err) {
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Create credential context */
    git_remote *remote_obj = NULL;
    char *remote_url = NULL;
    if (git_remote_lookup(&remote_obj, repo, remote_name) == 0) {
        const char *url = git_remote_url(remote_obj);
        if (url) {
            remote_url = strdup(url);
        }
        git_remote_free(remote_obj);
    }

    credential_context_t *cred_ctx = credential_context_create(remote_url);
    free(remote_url);

    /* Determine auto_pull setting: CLI --no-pull overrides config */
    bool auto_pull = opts->no_pull ? false : config->auto_pull;

    /* Determine divergence strategy: CLI overrides config */
    divergence_strategy_t diverged_strategy = parse_divergence_strategy(
        opts->diverged ? opts->diverged : config->diverged_strategy
    );

    /* Phase 2: Fetch from remote */
    err = sync_fetch_phase(repo, remote_name, sync_mode, &profiles, &results, out, opts->verbose, cred_ctx);
    if (err) {
        credential_context_free(cred_ctx);
        free(remote_name);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Phase 3: Analyze branch states */
    err = sync_analyze_phase(repo, remote_name, profiles, results, out);
    if (err) {
        credential_context_free(cred_ctx);
        free(remote_name);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    /* Phase 4: Sync with remote (push/pull/divergence handling) */
    err = sync_push_phase(repo, remote_name, results, out, opts->verbose,
                          auto_pull, diverged_strategy, cred_ctx,
                          config->confirm_destructive);
    if (err) {
        credential_context_free(cred_ctx);
        free(remote_name);
        sync_results_free(results);
        profile_list_free(profiles);
        config_free(config);
        output_free(out);
        return err;
    }

    credential_context_free(cred_ctx);
    free(remote_name);

    /* Final summary */
    output_section(out, "Sync complete");

    if (results->pushed_count > 0) {
        output_success(out, "%zu profile%s pushed",
                      results->pushed_count,
                      results->pushed_count == 1 ? "" : "s");
    }

    if (results->up_to_date_count > 0) {
        output_info(out, "%zu profile%s already up-to-date",
                   results->up_to_date_count,
                   results->up_to_date_count == 1 ? "" : "s");
    }

    if (results->need_pull_count > 0) {
        output_warning(out, "%zu profile%s need pull",
                      results->need_pull_count,
                      results->need_pull_count == 1 ? "" : "s");
    }

    if (results->diverged_count > 0) {
        output_warning(out, "%zu profile%s diverged (manual resolution needed)",
                      results->diverged_count,
                      results->diverged_count == 1 ? "" : "s");
    }

    if (results->failed_count > 0) {
        output_error(out, "%zu profile%s failed",
                    results->failed_count,
                    results->failed_count == 1 ? "" : "s");
    }

    if (results->fetch_failed_count > 0) {
        output_warning(out, "%zu fetch operation%s failed",
                      results->fetch_failed_count,
                      results->fetch_failed_count == 1 ? "" : "s");
    }

    if (results->auth_failed_count > 0) {
        output_error(out, "%zu authentication failure%s",
                    results->auth_failed_count,
                    results->auth_failed_count == 1 ? "" : "s");
    }

    /* Add trailing newline for UX consistency */
    if (out && out->stream) {
        fprintf(out->stream, "\n");
    }

    /* Cleanup */
    sync_results_free(results);
    profile_list_free(profiles);
    config_free(config);
        output_free(out);

    return NULL;
}
