/**
 * upstream.c - A branch against its remote
 */

#include "sys/upstream.h"

#include <git2.h>
#include <stdio.h>
#include <stdlib.h>

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
    *out = (upstream_info_t){ 0 };

    /* Build reference names */
    char local_refname[DOTTA_REFNAME_MAX];
    char remote_refname[DOTTA_REFNAME_MAX];
    error_t err;

    err = gitops_branch_refname(
        local_refname, sizeof(local_refname), profile_name
    );
    if (err) return err;

    err = gitops_remote_branch_refname(
        remote_refname, sizeof(remote_refname), remote_name, profile_name
    );
    if (err) return err;

    /* Each side's head, or its absence proven (sys/gitops.h gitops_reference_oid):
     * a packed-refs that will not parse is the analysis's failure, never a branch
     * or a remote branch that is not there. A symbolic branch is read through
     * to the one it names. */
    err = gitops_reference_oid(repo, local_refname, &out->local);
    if (err) return err;
    if (git_oid_is_zero(&out->local)) {
        out->state = UPSTREAM_NO_LOCAL;
        return NULL;
    }

    git_oid remote_oid;
    err = gitops_reference_oid(repo, remote_refname, &remote_oid);
    if (err) return err;
    if (git_oid_is_zero(&remote_oid)) {
        out->state = UPSTREAM_NO_REMOTE;
        return NULL;
    }

    /* Check if identical */
    if (git_oid_equal(&out->local, &remote_oid)) {
        out->state = UPSTREAM_UP_TO_DATE;
        return NULL;
    }

    /* Calculate ahead/behind */
    size_t ahead = 0, behind = 0;
    int rc = git_graph_ahead_behind(
        &ahead, &behind, repo, &out->local, &remote_oid
    );
    if (rc < 0) {
        return error_git(
            rc, "Cannot count the commits between '%s' and '%s'",
            local_refname, remote_refname
        );
    }

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
 * A state's glyph
 */
const char *upstream_state_symbol(upstream_state_t state) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:   return "=";
        case UPSTREAM_LOCAL_AHEAD:  return "↑";
        case UPSTREAM_REMOTE_AHEAD: return "↓";
        case UPSTREAM_DIVERGED:     return "↕";
        case UPSTREAM_NO_REMOTE:    return "•";
        case UPSTREAM_NO_LOCAL:     return "?";
    }

    CHECK_ARG(false, "an upstream state no enumerator names");
}

/**
 * A state's colour
 */
output_color_t upstream_state_color(upstream_state_t state) {
    switch (state) {
        case UPSTREAM_UP_TO_DATE:   return OUTPUT_COLOR_GREEN;
        case UPSTREAM_LOCAL_AHEAD:  return OUTPUT_COLOR_YELLOW;
        case UPSTREAM_REMOTE_AHEAD: return OUTPUT_COLOR_YELLOW;
        case UPSTREAM_DIVERGED:     return OUTPUT_COLOR_RED;
        case UPSTREAM_NO_REMOTE:    return OUTPUT_COLOR_CYAN;
        case UPSTREAM_NO_LOCAL:     return OUTPUT_COLOR_DIM;
    }

    CHECK_ARG(false, "an upstream state no enumerator names");
}

/**
 * A state's words, with the commits it counts
 */
void upstream_state_phrase(
    const upstream_info_t *info, char *buffer, size_t buffer_size
) {
    CHECK_NULL(info);
    CHECK_NULL(buffer);

    switch (info->state) {
        case UPSTREAM_UP_TO_DATE:
            snprintf(buffer, buffer_size, "up-to-date");
            return;

        case UPSTREAM_LOCAL_AHEAD:
            snprintf(
                buffer, buffer_size, "%zu commit%s ahead",
                info->ahead, info->ahead == 1 ? "" : "s"
            );
            return;

        case UPSTREAM_REMOTE_AHEAD:
            snprintf(
                buffer, buffer_size, "%zu commit%s behind",
                info->behind, info->behind == 1 ? "" : "s"
            );
            return;

        case UPSTREAM_DIVERGED:
            snprintf(
                buffer, buffer_size, "diverged (%zu ahead, %zu behind)",
                info->ahead, info->behind
            );
            return;

        case UPSTREAM_NO_REMOTE:
            snprintf(buffer, buffer_size, "no remote branch");
            return;

        case UPSTREAM_NO_LOCAL:
            snprintf(buffer, buffer_size, "no local branch");
            return;
    }

    CHECK_ARG(false, "an upstream state no enumerator names");
}
