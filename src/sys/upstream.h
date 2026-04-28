/**
 * upstream.h - Remote profile tracking and metadata
 *
 * Provides lightweight remote profile information for display in list/status.
 * Designed for minimal network overhead - fetches only refs, not full objects.
 */

#ifndef DOTTA_UPSTREAM_H
#define DOTTA_UPSTREAM_H

#include <git2.h>
#include <stdbool.h>
#include <types.h>

#include "base/output.h"

/**
 * Sync state for a profile relative to remote
 *
 * UNKNOWN encodes "no local branch": the analysis could not start.
 * NO_REMOTE encodes "local branch exists but no remote tracking branch."
 * The other four states all imply both branches exist.
 */
typedef enum {
    UPSTREAM_UP_TO_DATE,   /* Local and remote are identical */
    UPSTREAM_LOCAL_AHEAD,  /* Local has commits not on remote */
    UPSTREAM_REMOTE_AHEAD, /* Remote has commits not in local */
    UPSTREAM_DIVERGED,     /* Local and remote have diverged */
    UPSTREAM_NO_REMOTE,    /* No remote tracking branch exists */
    UPSTREAM_UNKNOWN       /* State could not be determined */
} upstream_state_t;

/**
 * Sync state plus commit counts.
 *
 * `ahead` and `behind` are meaningful only when state is one of
 * LOCAL_AHEAD / REMOTE_AHEAD / DIVERGED / UP_TO_DATE; for NO_REMOTE
 * and UNKNOWN they are zero.
 */
typedef struct {
    upstream_state_t state;
    size_t ahead;
    size_t behind;
} upstream_info_t;

/**
 * Analyze upstream state for a single profile
 *
 * Compares local branch with remote tracking branch to determine sync state.
 * Zero-initializes *out at function entry so the struct is in a defined
 * state on every code path; callers must not read *out after an error.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param profile_name Profile/branch name
 * @param out Upstream info (must not be NULL; populated on success)
 * @return Error or NULL on success
 */
error_t *upstream_analyze_profile(
    git_repository *repo,
    const char *remote_name,
    const char *profile_name,
    upstream_info_t *out
);

/**
 * Get compact symbol for upstream state
 *
 * Returns symbols like "=", "↑", "↓", "↕" for display
 */
const char *upstream_state_symbol(upstream_state_t state);

/**
 * Get display color for an upstream state.
 *
 * Sibling to upstream_state_symbol — pure function of state, no policy:
 *   UP_TO_DATE   → GREEN
 *   LOCAL_AHEAD  → YELLOW   (we have local changes to push)
 *   REMOTE_AHEAD → YELLOW   (remote has changes to pull)
 *   DIVERGED     → RED      (manual resolution required)
 *   NO_REMOTE    → CYAN     (informational, not an issue)
 *   UNKNOWN      → DIM      (state could not be determined)
 *
 * Centralizing the map keeps every display path in agreement on what each
 * state looks like.
 */
output_color_t upstream_state_color(upstream_state_t state);

/**
 * Discover remote branches that don't exist locally
 *
 * Scans LOCAL remote tracking refs (refs/remotes/<remote>/...) and identifies
 * branches that don't have corresponding local branches yet.
 *
 * **LOCAL OPERATION** - Does NOT contact the remote server.
 *
 * This function is useful after a fetch/clone when remote tracking refs exist
 * and you want to see what's available to create local branches from.
 *
 * **Limitation**: If a remote was just added without fetching, this returns
 * empty because no remote tracking refs exist yet. Use
 * gitops_list_remote_branches() instead to query the actual server.
 *
 * **Use cases:**
 * - After git clone, to show unfetched profiles
 * - After git fetch, to see what new branches are available
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param out_branches String array of branch names (caller must free)
 * @return Error or NULL on success
 */
error_t *upstream_discover_branches(
    git_repository *repo,
    const char *remote_name,
    string_array_t **out_branches
);

/**
 * Create local tracking branch from remote
 *
 * Creates a local branch that tracks a remote branch, setting the
 * local branch to point at the same commit as the remote.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param branch_name Branch name
 * @return Error or NULL on success
 */
error_t *upstream_create_tracking_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name
);

#endif /* DOTTA_UPSTREAM_H */
