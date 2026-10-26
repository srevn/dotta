/**
 * history.h - A branch's history, asked about paths
 *
 * Two questions of a history read back from a head through every parent: which
 * commits took each of a set of paths away (history_removals), and whether a
 * commit held each of a set of entries (history_held). "Holds" is Git's one-entry
 * rule: a blob of any filemode at the name; a subtree there, a gitlink, nothing,
 * or a blob or a gitlink above the name lacks it (core/profiles.h profile_entry's
 * rule, in Git's words).
 *
 * A commit took a path away — it is a removal of the path — where it lacks the
 * path and every parent holds it. A path the head holds has not left, and no
 * line of it is walked. Every other path is followed back through each parent
 * that lacks it, and each of its lines ends at a removal, at a root — a line
 * that never held it — or at an object that would not read.
 *
 * The removals' walk answers every path asked of one head: a commit is read once
 * for the paths that reach it, newest first by commit time, and a path reaching
 * a commit after its read is read there then — so clocks that skew against the
 * graph change what the walk costs, never what it answers. A commit's tree and
 * its parent's are descended together along the paths, and a subtree the two
 * share answers every path beneath it at once: a commit that touched none of
 * them costs a lookup at its root. A read that fails costs the paths whose lines
 * reach it, each unread, and nothing else.
 *
 * What a removal says of itself is the word its header names (sys/gitops.h
 * gitops_commit_action), carried opaque: what a word means is infra/commit's. A
 * header that will not read leaves the paths its commit took unread, its failure
 * minted once for each such commit (base/error.h): the walk's bound, and the
 * one failure it mints.
 *
 * A holding is any commit's, never a line's: an entry — a blob at a path, as a
 * kind — is held where a commit the head reaches holds that blob there as a blob
 * of that kind, and the store holds the blob. So no line is followed: one walk
 * of libgit2's reads each commit once for every entry asked past the same commit,
 * each entry done at its first holder, and a read that fails leaves unread the
 * entries it could have answered (history_held).
 *
 * Nothing is kept across calls. Over a tree a hand wrote out of Git's order, a
 * name's search can miss an entry the tree holds (lib/libgit2/src/libgit2/tree.c
 * entry_fromname, a binary search, beneath git_tree_entry_byname and
 * git_tree_entry_bypath alike), as every point question's does (core/profiles.h's
 * decode): either walk then reads a held name as lacking (stated).
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

/**
 * An entry a history may hold — a blob at a path, as a kind — and the commit
 * past which it is asked
 *
 * A tree entry's three facts: the storage path, the blob's id, and the filemode
 * whose kind the blob is asked under — a link, or a file of either blob filemode,
 * the executable bit being a claim's and never a kind. And `since`: a commit
 * whose history the caller has asked of this very entry already and found holding
 * none of it, so only what the head added past it is read; zero asks the history
 * whole.
 */
typedef struct {
    const char *path;            /* A storage path, validated */
    git_oid blob_oid;            /* The blob */
    git_filemode_t mode;         /* Its kind: GIT_FILEMODE_LINK, or either blob filemode */
    git_oid since;               /* A commit whose history held none of it, or zero: the whole */
} history_entry_t;

/**
 * Whether the history under `head` held each of a set of entries
 *
 * Per entry, parallel to `entries`, one of three answers:
 *   - held: a commit the head reaches past `since` holds the entry's blob at
 *     its path, as a blob of its kind, and the store holds that blob. The two
 *     halves are what "Git holds these bytes there" means: a store that lost an
 *     object may keep a tree naming it, which then holds nothing. The store's
 *     half is presence, never whether the blob reads (git_odb_exists);
 *   - unread: not held, and a commit or a tree it was owed would not read — the
 *     head's own among them — or the store would not open. What an unread history
 *     may hold is no answer, so a caller that keeps a "none" keeps it only where
 *     neither is set;
 *   - neither: the store lacks the blob; or the entry is asked since the head
 *     itself, which leaves nothing to read; or every commit it was owed was read,
 *     and none holds it.
 *
 * The store is asked first, once an entry, and an entry it lacks costs no commit,
 * as one asked since the head does. The rest are owed a walk, one a `since`,
 * each entry done at its first holder: libgit2's revwalk, newest first by commit
 * time, each commit's tree asked at the path of every entry still sought
 * (git_tree_entry_bypath), each directory on the way read again for each entry
 * and found in the run's tree cache (sys/gitops.c gitops_init).
 *   - Where `since` is zero the walk is unsorted, and reads nothing ahead of a
 *     commit but its parents (lib/libgit2/src/libgit2/revwalk.c get_revision:
 *     no sort and no hide, so no limit_list): a holder a few commits back costs
 *     a few commits, and an entry no commit held the history whole. A commit
 *     whose parent will not parse is never yielded, and the walk ends there
 *     (add_parents_to_list).
 *   - Past a commit, the walk hides it (git_revwalk_hide), which limits the walk:
 *     before the first commit is yielded, limit_list reads — commits, never trees
 *     — every commit the head reaches and `since` does not, and a slop of `since`'s
 *     own (still_interesting); clocks skewed against the graph can leave a few
 *     of `since`'s among those it yields, which `since`'s history holding none
 *     of the entry makes harmless. A commit that will not parse there fails the
 *     walk whole. A `since` the store no longer holds hides nothing, and the
 *     walk is whole: more than it was owed, never less.
 *
 * A history is immutable under its head's id, so the answer past `since` and
 * the caller's own up to it are together the answer for the history whole. No
 * failure is raised.
 *
 * Reader: core/workspace.c workspace_ask_bases.
 *
 * @param repo The repository the walks read (must not be NULL)
 * @param head The newest commit's id (must not be NULL)
 * @param entries The entries, in any order, one more than once (must not be NULL
 *                where count > 0)
 * @param count How many
 * @param held Whether each was held, parallel to `entries` (must not be NULL)
 * @param unread Whether each not held went unanswered, parallel to `entries`
 *               (must not be NULL)
 */
void history_held(
    git_repository *repo,
    const git_oid *head,
    const history_entry_t *entries,
    size_t count,
    bool *held,
    bool *unread
);

#endif /* DOTTA_HISTORY_H */
