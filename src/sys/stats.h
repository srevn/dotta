/**
 * stats.h - Git object and history statistics
 *
 * A blob's size, a commit's info, and a path's history. What a *profile* holds
 * is a different question — which tree paths are content and which are dotta's
 * own bookkeeping is knowledge this layer does not have — and is answered by
 * the profile's counts (core/profiles.h profile_counts), which read no blob;
 * the bytes a listing names are read through the primitive below by the listing
 * itself (cmds/list.c list_size_claim, list_files).
 *
 * A path's history is read along its lines. A commit changed a path where its
 * entry there — a blob, by its id and its filemode, or none: nothing at the name,
 * a subtree, a gitlink, or a blob or a gitlink above it — is no parent's own, a
 * root's parent being Git's empty tree, so a root changed what it holds. From a
 * commit that did not change the path, its line goes back through the first parent
 * whose entry is the commit's own, and through that one alone; from a commit
 * that changed it, through every parent. So a merge that took the path as one
 * side held it hands the line to that side, and what the side it discarded did
 * there is no part of the path's history, where a merge that composed the path
 * anew changed it. The rule is git's default simplification (lib/git/revision.c
 * try_to_simplify_commit), asked of one name: git's pathspec matches beneath a
 * directory of that name too, and a directory is no entry here.
 *
 * Two questions of the lines, each its own walk back from a head the caller read
 * once: each of a set of paths' last change, the first change its line meets —
 * no line parts before it (stats_last_changes); and one file's every change,
 * newest first (stats_file_history). A walk reads the commits on the lines and
 * no other, each asking the path of a parent's tree by name: a path the head
 * changed costs the head, however long the history behind it.
 */

#ifndef DOTTA_STATS_H
#define DOTTA_STATS_H

#include <git2.h>
#include <types.h>

/**
 * Commit information
 *
 * Lightweight commit metadata suitable for display, a value of the arena its
 * producer was given.
 */
typedef struct {
    git_oid oid;         /* Commit OID */
    const char *summary; /* First line of the message, trailing whitespace trimmed */
    git_time_t time;     /* Commit timestamp (seconds since epoch) */
} commit_info_t;

/**
 * File history
 *
 * The commits that changed one file along its lines, newest first.
 */
typedef struct {
    commit_info_t *commits;  /* The commits, the arena's */
    size_t count;            /* Number of commits */
} file_history_t;

/**
 * A commit's info, its summary copied into `arena`
 *
 * The summary is the message's first line with its trailing whitespace trimmed,
 * and empty for a commit with no message. The one producer of a commit_info_t:
 * every change the history walks answer, each branch head a verbose profile row
 * prints (cmds/list.c list_profiles), and each head beneath a verbose remote
 * row (cmds/status.c status_print_remote), so a row's commit and a file's read
 * alike.
 *
 * @param arena Arena the summary lives in (required)
 * @param commit The commit (required, borrowed)
 * @return The info, its summary `arena`'s
 */
commit_info_t stats_commit_info(arena_t *arena, const git_commit *commit);

/**
 * A blob's size, read efficiently
 *
 * Reads only object metadata using git_odb_read_header (no decompression). This
 * is 10-50x faster than git_blob_lookup for size-only queries.
 *
 * Acquires an ODB handle per call. A caller reading many sizes in one pass takes
 * the handle itself and uses stats_blob_size_with_odb below.
 *
 * @param repo Repository (required)
 * @param blob_oid Blob OID (required)
 * @param out Size in bytes (required, filled by function)
 * @return Error or NULL on success
 */
error_t stats_blob_size(
    git_repository *repo,
    const git_oid *blob_oid,
    size_t *out
);

/**
 * A blob's size, through a caller-held ODB handle
 *
 * The batch form of stats_blob_size: same metadata-only read, with the object
 * database acquired once by the caller (git_repository_odb) and reused across
 * the pass. The one place a blob's size is read without inflating it.
 *
 * @param odb Object database (required, borrowed)
 * @param blob_oid Blob OID (required)
 * @param out Size in bytes (required, filled by function)
 * @return Error or NULL on success
 */
error_t stats_blob_size_with_odb(
    git_odb *odb,
    const git_oid *blob_oid,
    size_t *out
);

/**
 * Each of a set of paths' last change
 *
 * Per path, parallel to `paths`: the first change its line meets back from
 * `head_oid` — the commit that made the entry the head holds, or where the head
 * holds none, the one that took the path away — or, where no commit on its line
 * held the path, none: the info zeroed. The names are the caller's: which of a
 * tree's blobs a screen reads is knowledge this layer does not have (the header),
 * so the reader hands in the listing it prints (cmds/list.c list_files). So is
 * the head: the commit the names were listed at, read once by the caller, so
 * the answers and the listing are one snapshot's whatever the branch says by
 * the time they are read — no branch is read here.
 *
 * One walk answers every path. Each path's line carries the entry the head holds
 * there, and waits at the commit it has reached; the newest such commit is read
 * next, once for every line waiting there, and its parents in order each take
 * the lines whose entry they hold. A line no parent takes ends there: the commit
 * is its path's last change. A line reaching a commit after its read — clocks
 * skewed against the graph — has it read again, which changes what the walk costs,
 * never what it answers.
 *
 * Reader: cmds/list.c list_files.
 *
 * @param repo Repository (required)
 * @param head_oid The head the names were listed at (required)
 * @param paths Storage paths, in any order, one more than once (required where
 *              count > 0)
 * @param count How many
 * @param arena Arena the answers and their summaries live in (required)
 * @param out The answers, parallel to `paths` (required; left as it was on a
 *            failure)
 * @return Error or NULL on success: a commit or a tree a line needs that will
 *         not read fails every answer, in Git's words naming the object
 */
error_t stats_last_changes(
    git_repository *repo,
    const git_oid *head_oid,
    const char *const *paths,
    size_t count,
    arena_t *arena,
    commit_info_t **out
);

/**
 * One file's every change
 *
 * The commits that changed `file_path` along its lines back from `head_oid`,
 * newest first by commit time, each read once however many lines reach it, and
 * none before the child its line came from. None is an answer — `out->count` 0
 * — whose words are the caller's (cmds/list.c list_file_history): a name no commit
 * on its lines held. The head is the caller's, read once, as stats_last_changes'
 * is.
 *
 * Reader: cmds/list.c list_file_history.
 *
 * @param repo Repository (required)
 * @param head_oid The head the history is read back from, read once by the caller
 *                (required)
 * @param file_path File path within tree (required)
 * @param arena Arena the commits and their summaries live in (required)
 * @param out File history (required; left as it was on a failure)
 * @return Error or NULL on success: a commit or a tree its lines need that will
 *         not read fails the history, in Git's words naming the object
 */
error_t stats_file_history(
    git_repository *repo,
    const git_oid *head_oid,
    const char *file_path,
    arena_t *arena,
    file_history_t *out
);

#endif /* DOTTA_STATS_H */
