/**
 * upstream.h - Remote profile tracking and metadata
 *
 * Provides lightweight remote profile information for display in list/status.
 * Designed for minimal network overhead - fetches only refs, not full objects.
 */

#ifndef DOTTA_UTILS_UPSTREAM_H
#define DOTTA_UTILS_UPSTREAM_H

#include <git2.h>
#include <stdbool.h>
#include <time.h>
#include <types.h>

/**
 * Sync state for a profile relative to remote
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
 * Remote profile metadata
 */
typedef struct {
    char *profile_name;          /* Profile/branch name */
    bool exists_locally;         /* Local branch exists */
    bool exists_remotely;        /* Remote tracking branch exists */
    upstream_state_t state;      /* Sync state */
    size_t ahead;                /* Commits ahead of remote */
    size_t behind;               /* Commits behind remote */
} upstream_info_t;

/**
 * List of upstream info for multiple profiles
 */
typedef struct {
    upstream_info_t *entries;
    size_t count;
    time_t fetched_at;           /* When remote refs were last fetched */
} upstream_info_list_t;

/**
 * Analyze upstream state for a single profile
 *
 * Compares local branch with remote tracking branch to determine sync state.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param profile_name Profile/branch name
 * @param out_info Upstream info (caller must free with upstream_info_free)
 * @return Error or NULL on success
 */
error_t *upstream_analyze_profile(
    git_repository *repo,
    const char *remote_name,
    const char *profile_name,
    upstream_info_t **out_info
);

/**
 * Free upstream info
 */
void upstream_info_free(upstream_info_t *info);

/**
 * Free upstream info list
 */
void upstream_info_list_free(upstream_info_list_t *list);

/**
 * Get string representation of upstream state
 *
 * Returns a human-readable string like "up-to-date", "ahead", "behind", etc.
 */
const char *upstream_state_string(upstream_state_t state);

/**
 * Get compact symbol for upstream state
 *
 * Returns symbols like "=", "↑", "↓", "↕" for display
 */
const char *upstream_state_symbol(upstream_state_t state);

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
 * empty because no remote tracking refs exist yet. Use upstream_query_remote_branches()
 * instead to query the actual server.
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
 * Query remote server for available branches
 *
 * **NETWORK OPERATION** - Connects to the remote server to query ALL branches
 * that exist on the server, regardless of local state.
 *
 * This is the authoritative source for what's on the remote, unlike
 * upstream_discover_branches() which only looks at cached local metadata.
 *
 * **Use cases:**
 * - Listing remote profiles without fetching (profile list --remote)
 * - Fetching all profiles (profile fetch --all)
 * - Validating branch existence before operations
 * - When remote was just added and no tracking refs exist yet
 *
 * **Requirements:**
 * - Network connectivity
 * - Credentials if repository requires authentication
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param cred_ctx Credential context for authentication (may be NULL)
 * @param out_branches String array of branch names on remote (caller must free)
 * @return Error or NULL on success
 */
error_t *upstream_query_remote_branches(
    git_repository *repo,
    const char *remote_name,
    void *cred_ctx,
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

/**
 * Detect default remote name for tracking
 *
 * Strategy:
 *   1. Prefer "origin" if it exists (standard convention)
 *   2. If exactly one remote, use it
 *   3. If multiple remotes without origin, error (require explicit choice)
 *   4. If no remotes, error with helpful hint
 *
 * @param repo Repository (must not be NULL)
 * @param out_remote Remote name (caller must free)
 * @return Error or NULL on success
 */
error_t *upstream_detect_remote(git_repository *repo, char **out_remote);

#endif /* DOTTA_UTILS_UPSTREAM_H */
