/**
 * upstream.h - A branch against its remote
 *
 * Read off the remote-tracking refs the last fetch left, and nothing here contacts
 * the remote: a branch's state against its remote (upstream_analyze_profile)
 * and the face every screen gives that state — its glyph, its colour and its
 * phrase — then the remote's branches made local (upstream_discover_branches,
 * upstream_ensure_tracking_branch).
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
 * Two answers say a side is absent, each proven (sys/gitops.h
 * gitops_reference_oid): NO_LOCAL, no local branch, so there is nothing to compare;
 * NO_REMOTE, a local branch and no remote tracking branch. The other four states
 * imply both branches exist. A side that could not be read is no state: it is
 * the analysis's error.
 */
typedef enum {
    UPSTREAM_UP_TO_DATE,   /* Local and remote are identical */
    UPSTREAM_LOCAL_AHEAD,  /* Local has commits not on remote */
    UPSTREAM_REMOTE_AHEAD, /* Remote has commits not in local */
    UPSTREAM_DIVERGED,     /* Local and remote have diverged */
    UPSTREAM_NO_REMOTE,    /* No remote tracking branch exists */
    UPSTREAM_NO_LOCAL      /* No local branch exists */
} upstream_state_t;

/**
 * Sync state plus commit counts.
 *
 * `ahead` and `behind` are meaningful only when state is one of LOCAL_AHEAD /
 * REMOTE_AHEAD / DIVERGED / UP_TO_DATE; for NO_REMOTE and NO_LOCAL they are zero.
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
 * Zero-initializes *out at function entry so the struct is in a defined state
 * on every code path; callers must not read *out after an error.
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param profile_name Profile/branch name
 * @param out Upstream info (must not be NULL; populated on success)
 * @return Error or NULL on success
 */
error_t upstream_analyze_profile(
    git_repository *repo,
    const char *remote_name,
    const char *profile_name,
    upstream_info_t *out
);

/**
 * A state's glyph: "=", "↑", "↓", "↕", "•" or "?"
 *
 * One of the three faces of a state, beside its colour (upstream_state_color)
 * and its phrase (upstream_state_phrase). Centralizing the map keeps every display
 * path in agreement on what each state looks like.
 *
 * Readers: cmds/status.c status_print_remote; cmds/sync.c sync_print_lead;
 * cmds/profile.c profile_fetch; cmds/list.c list_profiles.
 */
const char *upstream_state_symbol(upstream_state_t state);

/**
 * A state's colour
 *
 * Sibling to upstream_state_symbol, read where it is — pure function of state,
 * no policy:
 *   UP_TO_DATE   → GREEN
 *   LOCAL_AHEAD  → YELLOW   (we have local changes to push)
 *   REMOTE_AHEAD → YELLOW   (remote has changes to pull)
 *   DIVERGED     → RED      (manual resolution required)
 *   NO_REMOTE    → CYAN     (informational, not an issue)
 *   NO_LOCAL     → DIM      (no local branch to compare)
 */
output_color_t upstream_state_color(upstream_state_t state);

#define UPSTREAM_PHRASE_MAX 72 /* "diverged (%zu ahead, %zu behind)" at a size_t's widest, and NUL */

/**
 * A state's words, with the commits it counts
 *
 * "up-to-date", "1 commit ahead", "2 commits behind", "diverged (1 ahead, 2
 * behind)", "no remote branch", "no local branch": the phrase, not its frame —
 * each reader sets the glyph and the colour beside it (upstream_state_symbol,
 * upstream_state_color) and the frame its screen gives a state, so the rows of
 * status, list, sync and profile fetch say a state alike.
 *
 * The words on screen: a state named alone, without its counts — status's Sync
 * summary counting the branches in each state (cmds/status.c status_print_remote)
 * — takes the phrase's word for it: up-to-date, ahead, behind, diverged, no remote
 * branch, no local branch. No key decodes the glyph, on a screen or in a help:
 * every row that prints one prints the phrase beside it.
 *
 * Readers: cmds/status.c status_print_remote, cmds/list.c list_profiles, whose
 * rows take status's compact frame, cmds/sync.c sync_print_state, cmds/profile.c
 * profile_fetch.
 *
 * @param info The state and its counts (must not be NULL)
 * @param buffer Output buffer for the phrase (must not be NULL)
 * @param buffer_size Size of output buffer: UPSTREAM_PHRASE_MAX
 */
void upstream_state_phrase(
    const upstream_info_t *info,
    char *buffer,
    size_t buffer_size
);

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
 * **Limitation**: If a remote was just added without fetching, this returns empty
 * because no remote tracking refs exist yet. Use gitops_list_remote_branches()
 * instead to query the actual server.
 *
 * **Use cases:**
 * - After git clone, to show unfetched profiles
 * - After git fetch, to see what new branches are available
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param arena Arena the answer and both listings it is read from live in (must
 *              not be NULL)
 * @param out The branch names, in the remote listing's order (must not be NULL;
 *            left as it was on a failure)
 * @return Error or NULL on success
 */
error_t upstream_discover_branches(
    git_repository *repo,
    const char *remote_name,
    arena_t *arena,
    string_array_t *out
);

/**
 * Make a remote branch local, or leave the local one where it stands
 *
 * A local branch of the name exists after the call. One already here is left as
 * it is: a fetch moves the remote-tracking ref and never the local branch — merging
 * the two is sync's, through sys/resolve. One absent is created at the remote's
 * commit.
 *
 * Refuses with ERR_CONFLICT, naming both branches, when the local ref namespace
 * cannot hold the name beside one already there (`gitops_branch_blocker`) — a
 * failure about the two names rather than the wire, which the ref write would
 * otherwise report in libgit2's own words — and with ERR_CONFLICT in the writer's
 * words where a branch of the name was made since the look: the create is written
 * only where the name is still free (sys/gitops.h gitops_write_reference).
 *
 * Readers: cmds/clone.c land_profiles, every profile the clone chose — a name
 * given twice is here at its second; cmds/profile.c profile_fetch, a profile
 * its analysis found no local branch for (upstream_analyze_profile).
 *
 * @param repo Repository (must not be NULL)
 * @param remote_name Remote name (e.g., "origin")
 * @param branch_name Branch name
 * @return Error or NULL on success
 */
error_t upstream_ensure_tracking_branch(
    git_repository *repo,
    const char *remote_name,
    const char *branch_name
);

#endif /* DOTTA_UPSTREAM_H */
