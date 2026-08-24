/**
 * stats.h - Git object and history statistics
 *
 * Provides efficient statistics gathering over blobs and commit history. What a
 * *profile* holds is a different question — which tree paths are content and
 * which are dotta's own bookkeeping is knowledge this layer does not have — and
 * is answered by profile_get_stats (core/profiles.h), which reads blob sizes
 * through the primitive below.
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
 * Lightweight commit metadata suitable for display.
 */
typedef struct {
    git_oid oid;         /* Commit OID */
    char *summary;       /* First line of commit message (caller must free) */
    git_time_t time;     /* Commit timestamp (seconds since epoch) */
} commit_info_t;

/**
 * File→commit mapping
 *
 * Maps each file path to its most recent commit. Optimized for the use case:
 * "for each file in current tree, get last commit"
 *
 * Internal implementation is opaque. Use accessor functions.
 */
typedef struct file_commit_map file_commit_map_t;

/**
 * File history
 *
 * List of all commits that modified a specific file, in reverse chronological
 * order (newest first).
 */
typedef struct {
    commit_info_t *commits;  /* Array of commits (caller must free with stats_free_file_history) */
    size_t count;            /* Number of commits */
} file_history_t;

/**
 * Get blob size efficiently
 *
 * Reads only object metadata using git_odb_read_header (no decompression). This
 * is 10-50x faster than git_blob_lookup for size-only queries.
 *
 * Acquires an ODB handle per call. A caller reading many sizes in one pass takes
 * the handle itself and uses stats_get_blob_size_with_odb below.
 *
 * @param repo Repository (required)
 * @param blob_oid Blob OID (required)
 * @param out Size in bytes (required, filled by function)
 * @return Error or NULL on success
 */
error_t *stats_get_blob_size(
    git_repository *repo,
    const git_oid *blob_oid,
    size_t *out
);

/**
 * Get blob size through a caller-held ODB handle
 *
 * The batch form of stats_get_blob_size: same metadata-only read, with the object
 * database acquired once by the caller (git_repository_odb) and reused across
 * the pass. The one place a blob's size is read without inflating it.
 *
 * @param odb Object database (required, borrowed)
 * @param blob_oid Blob OID (required)
 * @param out Size in bytes (required, filled by function)
 * @return Error or NULL on success
 */
error_t *stats_get_blob_size_with_odb(
    git_odb *odb,
    const git_oid *blob_oid,
    size_t *out
);

/**
 * Build file→commit mapping
 *
 * Walks commit history from newest to oldest, building a mapping from each file
 * (in the given tree) to its most recent commit.
 *
 * Optimization: Stops early when all files in tree have been found. This makes
 * the operation much faster for profiles where files were modified recently (common
 * case).
 *
 * Performance: O(commits_needed × files_per_commit) - with early termination
 * Memory: O(files_in_tree) - one commit_info per file
 *
 * Note: This is expensive (history walk). Use only in verbose mode.
 *
 * @param repo Repository (required)
 * @param branch_name Branch name (required, e.g., "global")
 * @param tree Tree containing files to track (required)
 * @param out File→commit map (required, caller must free with
 *            stats_free_file_commit_map)
 * @return Error or NULL on success
 */
error_t *stats_build_file_commit_map(
    git_repository *repo,
    const char *branch_name,
    git_tree *tree,
    file_commit_map_t **out
);

/**
 * Get file history
 *
 * Returns all commits that modified the specified file, in reverse chronological
 * order (newest first).
 *
 * Performance: O(total_commits) - walks entire branch history Memory:
 * O(matching_commits) - allocates array for all commits touching file
 *
 * Note: This is very expensive. Use only when user explicitly requests file history
 *       (e.g., `dotta list -p <profile> <file>`).
 *
 * @param repo Repository (required)
 * @param branch_name Branch name (required)
 * @param file_path File path within tree (required)
 * @param out File history (required, caller must free with stats_free_file_history)
 * @return Error or NULL on success
 */
error_t *stats_get_file_history(
    git_repository *repo,
    const char *branch_name,
    const char *file_path,
    file_history_t **out
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
 * @return Commit info (borrowed pointer, valid until map is freed) or NULL if
 *         not found
 */
const commit_info_t *stats_file_commit_map_get(
    const file_commit_map_t *map,
    const char *file_path
);

/**
 * Free commit info
 *
 * Generic callback signature for use with containers (e.g., hashmap_free). Accepts
 * void* to match standard C cleanup callback pattern.
 *
 * @param ptr Commit info to free (NULL safe)
 */
void stats_free_commit_info(void *ptr);

/**
 * Free file→commit map
 *
 * @param map Map to free (NULL safe)
 */
void stats_free_file_commit_map(file_commit_map_t *map);

/**
 * Free file history
 *
 * @param history History to free (NULL safe)
 */
void stats_free_file_history(file_history_t *history);

#endif /* DOTTA_STATS_H */
