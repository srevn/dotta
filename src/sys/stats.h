/**
 * stats.h - Git object and history statistics
 *
 * Provides efficient statistics gathering over blobs and commit history. What a
 * *profile* holds is a different question — which tree paths are content and
 * which are dotta's own bookkeeping is knowledge this layer does not have — and
 * is answered by the profile's counts (core/profiles.h profile_counts), which
 * read no blob; the bytes a listing names are read through the primitive below
 * by the listing itself (cmds/list.c list_size_claim, list_files).
 *
 * Design principles:
 * - Minimize expensive operations (commit walking deferred to verbose mode)
 * - Single-pass algorithms where possible
 * - Early termination optimizations
 * - Const-correct interfaces
 *
 * Performance characteristics:
 * - Blob size: O(1) - one object-header read, no decompression
 * - File commit map: O(commits_needed × files_per_commit) - with early termination
 * - File history: O(total_commits) - walks entire history
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
 * File→commit mapping
 *
 * Maps each file path to its most recent commit. Optimized for the use case:
 * "for each file in current tree, get last commit"
 *
 * Internal implementation is opaque. Use accessor functions. The map, its keys
 * and every commit it holds are the arena's it was built in: nothing frees one.
 */
typedef struct file_commit_map file_commit_map_t;

/**
 * File history
 *
 * List of all commits that modified a specific file, in reverse chronological
 * order (newest first).
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
 * every commit the history walks keep, and each branch head a verbose profile
 * row prints (cmds/list.c list_profiles), so a row's commit and a file's read
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
 * Build file→commit mapping
 *
 * Walks the history from `head_oid` back, newest to oldest, mapping each of `paths`
 * to the most recent commit that touched it. The names are the caller's: which
 * of a tree's blobs a screen reads is knowledge this layer does not have (the
 * header), so the reader hands in the listing it prints — the profile's content,
 * never its machinery (cmds/list.c list_files) — and the map holds those names
 * and no other. So is the head: the commit the names were listed at, read once
 * by the caller, so the map and the listing are one snapshot's whatever the branch
 * says by the time the map is built — no branch is read here.
 *
 * Stops early once every name is mapped, which makes a history whose listed files
 * all changed recently cheap however long it is. Each name is met first at its
 * newest commit, so stopping sooner changes no answer.
 *
 * Performance: O(commits_needed × files_per_commit) - with early termination
 * Memory: O(paths) - one slot per name, and one commit_info per commit that maps
 * a name, shared by every name it maps
 *
 * Note: This is expensive (history walk). Use only in verbose mode.
 *
 * @param repo Repository (required)
 * @param head_oid The head the names were listed at (required)
 * @param paths The names to map: storage paths that commit's tree holds (required)
 * @param arena Arena the map, its keys and its commits live in (required)
 * @param out File→commit map (required; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t stats_build_file_commit_map(
    git_repository *repo,
    const git_oid *head_oid,
    const string_array_t *paths,
    arena_t *arena,
    file_commit_map_t **out
);

/**
 * The commits that touched one file
 *
 * Returns every commit from `head_oid` back that modified the specified file,
 * in reverse chronological order (newest first). None is an answer — `out->count`
 * 0 — whose words are the caller's (cmds/list.c list_file_history).
 *
 * Performance: O(total_commits) - walks entire branch history Memory:
 * O(matching_commits) - allocates array for all commits touching file
 *
 * Note: This is very expensive. Use only when user explicitly requests file history
 *       (e.g., `dotta list -p <profile> <file>`).
 *
 * @param repo Repository (required)
 * @param head_oid The head the history is read back from, read once by the caller
 *                (required)
 * @param file_path File path within tree (required)
 * @param arena Arena the commits and their summaries live in (required)
 * @param out File history (required; left as it was on a failure)
 * @return Error or NULL on success
 */
error_t stats_file_history(
    git_repository *repo,
    const git_oid *head_oid,
    const char *file_path,
    arena_t *arena,
    file_history_t *out
);

/**
 * Lookup commit info for a file
 *
 * Returns the commit info for the specified file path, or NULL if the file is
 * not in the map.
 *
 * Performance: O(1) - constant time hashmap lookup
 *
 * @param map File→commit map (required)
 * @param file_path File path (required)
 * @return Commit info (the map's arena's) or NULL if not found
 */
const commit_info_t *stats_file_commit_map_get(
    const file_commit_map_t *map,
    const char *file_path
);

#endif /* DOTTA_STATS_H */
