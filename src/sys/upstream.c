/**
 * upstream.c - Remote profile tracking and metadata implementation
 */

#include "sys/upstream.h"

#include <git2.h>
#include <stdlib.h>

#include "base/arena.h"
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

    /* Each side's tip, or its absence proven (sys/gitops.h gitops_reference_oid):
     * a packed-refs that will not parse is the analysis's failure, never a branch
     * or a remote branch that is not there. A symbolic branch is read through
     * to the one it names. */
    git_oid local_oid;
    err = gitops_reference_oid(repo, local_refname, &local_oid);
    if (err) return err;
    if (git_oid_is_zero(&local_oid)) {
        return NULL;                  /* no local branch: UNKNOWN, set above */
    }

    git_oid remote_oid;
    err = gitops_reference_oid(repo, remote_refname, &remote_oid);
    if (err) return err;
    if (git_oid_is_zero(&remote_oid)) {
        out->state = UPSTREAM_NO_REMOTE;
        return NULL;
    }

    /* Check if identical */
    if (git_oid_equal(&local_oid, &remote_oid)) {
        out->state = UPSTREAM_UP_TO_DATE;
        return NULL;
    }

    /* Calculate ahead/behind */
    size_t ahead = 0, behind = 0;
    int rc = git_graph_ahead_behind(
        &ahead, &behind, repo, &local_oid, &remote_oid
    );
    if (rc < 0) return error_from_git(rc);

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
        case UPSTREAM_UNKNOWN:      return OUTPUT_COLOR_DIM;
    }
    CHECK_ARG(false, "an upstream state no enumerator names");
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
    error_t err = gitops_list_remote_tracking(repo, remote_name, arena, &remote_branches);
    if (err) return err;

    string_array_t local_branches;
    err = gitops_list_branches(repo, arena, &local_branches);
    if (err) return err;

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
    error_t err = gitops_branch_exists(repo, branch_name, &exists);
    if (err) return err;
    if (exists) return NULL;

    /* A name Git's ref namespace cannot hold beside the ones already here. The
     * remote cannot ship a colliding pair — Git forbids it there too — so the
     * blocker is always a local branch: a profile added on this machine and never
     * pushed, standing where a fetched one would go. Refused by name, ahead of
     * the ref write whose own message names only one of the two. The listing
     * the blocker is read from is a frame of this call's own: what the call answers
     * is no memory, and the refusal copies the name. */
    arena_t *frame = arena_create(0);
    const char *blocker = NULL;
    err = gitops_branch_blocker(repo, branch_name, frame, &blocker);
    if (!err && blocker) {
        err = ERROR(
            ERR_CONFLICT,
            "Branch '%s' already exists, and Git cannot hold '%s' beside it: "
            "one is a name, the other a folder of names", blocker, branch_name
        );
    }
    arena_free(frame);
    if (err) return err;

    /* Get remote ref */
    git_oid target_oid;
    err = gitops_resolve_remote_branch_oid(
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
