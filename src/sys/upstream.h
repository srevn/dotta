/**
 * upstream.h - A branch against its tracking ref, as sync reads it
 *
 * Read off the remote-tracking refs the session's last fetch wrote (sys/remote.h
 * remote_fetch), and nothing here contacts the remote: a branch's state against
 * its tracking ref (upstream_analyze_profile), the two-way reading sync decides
 * by, and the face sync's rows give that state — its glyph, its colour and its
 * phrase. Every other screen reads a branch against its remote three ways, the
 * remote's own listing beside the tracking ref (sys/remote.h remote_relation_t).
 * Readers: cmds/sync.c sync_analyze, each row its run decides by, and sys/resolve.c
 * resolve_verify, after a resolution.
 */

#ifndef DOTTA_UPSTREAM_H
#define DOTTA_UPSTREAM_H

#include <git2.h>
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
 * Sync state plus commit counts, and the branch's head as the analysis read it.
 *
 * `ahead` and `behind` are meaningful only when state is one of LOCAL_AHEAD /
 * REMOTE_AHEAD / DIVERGED / UP_TO_DATE; for NO_REMOTE and NO_LOCAL they are zero.
 * `local` is the head every state was read from, Git's null id for NO_LOCAL:
 * what a push of the branch sends (cmds/sync.c sync_push), never a second read
 * of it.
 */
typedef struct {
    upstream_state_t state;
    size_t ahead;
    size_t behind;
    git_oid local;
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
 * and its phrase (upstream_state_phrase), each the one sys/remote.h gives the
 * same reading (remote_state_symbol, remote_state_color, remote_state_phrase),
 * so sync's rows look as status's do.
 *
 * Reader: cmds/sync.c sync_print_lead.
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
 *
 * Reader: cmds/sync.c sync_print_lead.
 */
output_color_t upstream_state_color(upstream_state_t state);

#define UPSTREAM_PHRASE_MAX 72 /* "diverged (%zu ahead, %zu behind)" at a size_t's widest, and NUL */

/**
 * A state's words, with the commits it counts
 *
 * "up-to-date", "1 commit ahead", "2 commits behind", "diverged (1 ahead, 2
 * behind)", "no remote branch", "no local branch": the phrase, not its frame —
 * the reader sets the glyph and the colour beside it (upstream_state_symbol,
 * upstream_state_color) and the frame its screen gives a state. No key decodes
 * the glyph, on a screen or in a help: every row that prints one prints the phrase
 * beside it.
 *
 * Reader: cmds/sync.c sync_print_state.
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

#endif /* DOTTA_UPSTREAM_H */
