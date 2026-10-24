/**
 * history.h - A branch's history, asked about paths
 *
 * Which commits took each of a set of paths away, read back from a head through
 * every parent. A commit took a path away — it is a removal of the path — where
 * it lacks the path and every parent holds it. "Holds" is Git's one-entry rule:
 * a blob of any filemode at the name; a subtree there, a gitlink, nothing, or a
 * blob or a gitlink above the name lacks it (core/profiles.h profile_entry's
 * rule, in Git's words). A path the head holds has not left, and no line of it
 * is walked. Every other path is followed back through each parent that lacks
 * it, and each of its lines ends at a removal, at a root — a line that never
 * held it — or at an object that would not read.
 *
 * One walk answers every path asked of one head: a commit is read once for the
 * paths that reach it, newest first by commit time, and a path reaching a commit
 * after its read is read there then — so clocks that skew against the graph change
 * what the walk costs, never what it answers. A commit's tree and its parent's
 * are descended together along the paths, and a subtree the two share answers
 * every path beneath it at once: a commit that touched none of them costs a lookup
 * at its root. A read that fails costs the paths whose lines reach it, each unread,
 * and nothing else.
 *
 * What a removal says of itself is the word its header names (sys/gitops.h
 * gitops_commit_action), carried opaque: what a word means is infra/commit's. A
 * header that will not read leaves the paths its commit took unread, its failure
 * minted once for each such commit (base/error.h): the walk's bound, and the
 * one failure it mints. Nothing is kept across calls.
 *
 * Over a tree a hand wrote out of Git's order, a name's search can miss an entry
 * the tree holds (lib/libgit2/src/libgit2/tree.c git_tree_entry_byname, a binary
 * search), as every point question's does (core/profiles.h's decode): the walk
 * then reads a held name as lacking (stated).
 */

#ifndef DOTTA_HISTORY_H
#define DOTTA_HISTORY_H

#include <git2.h>
#include <types.h>

/**
 * A commit that took a path away, and what it says of itself
 */
typedef struct {
    git_oid oid;                 /* The commit: lacks the path, and every parent holds it */
    const char *action;          /* The word its header names; NULL where it names none */
} history_removal_t;

/**
 * What a branch's history says of one path
 *
 * Held, where the head holds it: no removal, no line walked. Else the removals
 * its lines ended at — one a line at most, several only where lines part at a
 * merge — and whether a line went unread, which may stand beside a removal another
 * line ended at. No removal and every line read is a path no commit of the history
 * held.
 */
typedef struct {
    const history_removal_t *entries; /* The removals, in the order the walk met them */
    size_t count;
    bool held;                        /* The head holds the path */
    bool unread;                      /* A commit or a tree on one of its lines would not read */
} history_removals_t;

/**
 * Which commits under `head` took each path away
 *
 * Per path, parallel to `paths`: held, or the removals its lines ended at and
 * whether a line went unread. No failure is raised: a read that fails is the
 * paths' `unread`, the head's own tree the first such read.
 *
 * Reader: core/profiles.c profile_departures.
 *
 * @param head The newest commit; the walk reads its repository (git_commit_owner)
 *             (must not be NULL)
 * @param paths Storage paths, validated, in any order, one more than once (must
 *              not be NULL where count > 0)
 * @param count How many
 * @param arena The answers' removals and words (must not be NULL)
 * @param out The answers, parallel to `paths` (must not be NULL)
 */
void history_removals(
    const git_commit *head,
    const char *const *paths,
    size_t count,
    arena_t *arena,
    history_removals_t *out
);

#endif /* DOTTA_HISTORY_H */
