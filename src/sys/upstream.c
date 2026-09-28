/**
 * upstream.c - Remote profile tracking and metadata implementation
 */

#include "sys/upstream.h"

#include <git2.h>
#include <stdlib.h>

#include "base/array.h"
#include "base/error.h"
#include "sys/gitops.h"

/**
 * Analyze upstream state for a single profile
 */
error_t upstream_analyze_profile(
    git_repository *repo,
    const char *remote_name,
    const char *profile_name,
    upstream_info_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(profile_name);
    CHECK_NULL(out);

    /* Defined-state on every path; callers must not read after error. */
    *out = (upstream_info_t){ .state = UPSTREAM_UNKNOWN };

    /* Build reference names */
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t err;

    err = gitops_branch_refname(
        local_refname, sizeof(local_refname), profile_name
    );
    if (err) return err;

    err = gitops_build_refname(
        remote_refname, sizeof(remote_refname), "refs/remotes/%s/%s",
        remote_name, profile_name
    );
    if (err) {
        return error_wrap(
            err, "Invalid remote/profile name '%s/%s'",
            remote_name, profile_name
        );
    }

    /* Local branch absent → UNKNOWN (already set above). */
    git_reference *local_ref = NULL;
    int git_err = git_reference_lookup(&local_ref, repo, local_refname);
    if (git_err == GIT_ENOTFOUND) {
        return NULL;
    } else if (git_err < 0) {
        return error_from_git(git_err);
    }

    /* Remote branch absent → NO_REMOTE. */
    git_reference *remote_ref = NULL;
    git_err = git_reference_lookup(&remote_ref, repo, remote_refname);
    if (git_err == GIT_ENOTFOUND) {
        git_reference_free(local_ref);
        out->state = UPSTREAM_NO_REMOTE;
        return NULL;
    } else if (git_err < 0) {
        git_reference_free(local_ref);
        return error_from_git(git_err);
    }

    /* Get OIDs */
    const git_oid *local_oid = git_reference_target(local_ref);
    const git_oid *remote_oid = git_reference_target(remote_ref);

    if (!local_oid || !remote_oid) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        return ERROR(ERR_GIT, "Branch reference has no target OID");
    }

    /* Check if identical */
    if (git_oid_equal(local_oid, remote_oid)) {
        git_reference_free(local_ref);
        git_reference_free(remote_ref);
        out->state = UPSTREAM_UP_TO_DATE;
        return NULL;
    }

    /* Calculate ahead/behind */
    size_t ahead = 0, behind = 0;
    git_err = git_graph_ahead_behind(
        &ahead, &behind, repo, local_oid, remote_oid
    );
    git_reference_free(local_ref);
    git_reference_free(remote_ref);

    if (git_err < 0) return error_from_git(git_err);

    out->ahead = ahead;
    out->behind = behind;

    if (ahead > 0 && behind == 0) {
        out->state = UPSTREAM_LOCAL_AHEAD;
    } else if (ahead == 0 && behind > 0) {
        out->state = UPSTREAM_REMOTE_AHEAD;
    } else if (ahead > 0 && behind > 0) {
        out->state = UPSTREAM_DIVERGED;
    } else {
        out->state = UPSTREAM_UP_TO_DATE;
    }

    return NULL;
}

/**
 * Get compact symbol for upstream state
 */
const char *upstream_state_symbol(upstream_state_t state) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:   return "=";
        case UPSTREAM_LOCAL_AHEAD:  return "↑";
        case UPSTREAM_REMOTE_AHEAD: return "↓";
        case UPSTREAM_DIVERGED:     return "↕";
        case UPSTREAM_NO_REMOTE:    return "•";
        case UPSTREAM_UNKNOWN:      return "?";
    }
    CHECK_ARG(false, "an upstream state no enumerator names");
}

/**
 * Get display color for upstream state
 */
output_color_t upstream_state_color(upstream_state_t state) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:   return OUTPUT_COLOR_GREEN;
        case UPSTREAM_LOCAL_AHEAD:  return OUTPUT_COLOR_YELLOW;
        case UPSTREAM_REMOTE_AHEAD: return OUTPUT_COLOR_YELLOW;
        case UPSTREAM_DIVERGED:     return OUTPUT_COLOR_RED;
        case UPSTREAM_NO_REMOTE:    return OUTPUT_COLOR_CYAN;
        case UPSTREAM_UNKNOWN:
        default:                    return OUTPUT_COLOR_DIM;
    }
}

/**
 * Discover remote branches that don't exist locally
 */
error_t upstream_discover_branches(
    git_repository *repo,
    const char *remote_name,
    arena_t *arena,
    string_array_t *out
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(arena);
    CHECK_NULL(out);

    /* Every remote tracking branch, and every local one: both listings are the
     * answer's arena's */
    string_array_t remote_branches;
    RETURN_IF_ERROR(gitops_list_remote_tracking(repo, remote_name, arena, &remote_branches));

    string_array_t local_branches;
    RETURN_IF_ERROR(gitops_list_branches(repo, arena, &local_branches));

    /* Set difference, in place and in the remote's order: what is here already
     * leaves the remote listing, which is then the answer */
    for (size_t i = remote_branches.count; i-- > 0;) {
        if (string_array_contains(&local_branches, remote_branches.entries[i])) {
            string_array_remove(&remote_branches, i);
        }
    }

    *out = remote_branches;
    return NULL;
}

/**
 * Make a remote branch local, or leave the local one where it stands
 */
error_t upstream_ensure_tracking_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name
) {
    CHECK_NULL(repo);
    CHECK_NULL(remote_name);
    CHECK_NULL(branch_name);

    /* Already here: a fetch never moves a local branch. */
    bool exists = false;
    RETURN_IF_ERROR(gitops_branch_exists(repo, branch_name, &exists));
    if (exists) return NULL;

    /* A name Git's ref namespace cannot hold beside the ones already here. The
     * remote cannot ship a colliding pair — Git forbids it there too — so the
     * blocker is always a local branch: a profile added on this machine and never
     * pushed, standing where a fetched one would go. Refused by name, ahead of
     * the ref write whose own message names only one of the two. */
    char blocker[DOTTA_REFNAME_MAX];
    RETURN_IF_ERROR(gitops_branch_blocker(repo, branch_name, blocker, sizeof(blocker)));
    if (blocker[0]) {
        return ERROR(
            ERR_CONFLICT,
            "Branch '%s' already exists, and Git cannot hold '%s' beside it: "
            "one is a name, the other a folder of names", blocker, branch_name
        );
    }

    /* Get remote ref */
    git_oid target_oid;
    error_t err = gitops_resolve_remote_branch_oid(
        repo, remote_name, branch_name, &target_oid
    );
    if (err) return err;

    /* Create local branch pointing to the same commit */
    char local_refname[DOTTA_REFNAME_MAX];
    err = gitops_branch_refname(
        local_refname, sizeof(local_refname), branch_name
    );
    if (err) return err;

    return gitops_create_reference(repo, local_refname, &target_oid, false);
}
